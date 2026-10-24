#include "cycle_energy.h"
#include "crypto_app.h"
#include "hardware_control.h"
#include "mqtt_app.h"
#include "esp_timer.h"
#include "esp_rom_sys.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

typedef struct {
    bool busy,active,ended,aes,aborted,interference,network_bad;
    char id[17],ids[200][17];
    unsigned target,count,samples,errors;
    int64_t armed,start,end,last,first,max_gap,covered;
    double energy,vsum,isum,last_w,last_v,last_i;
} capture_t;
static capture_t c,finished;
static portMUX_TYPE mux=portMUX_INITIALIZER_UNLOCKED;
static const unsigned char aad_topic[]=CYCLE_ENERGY_REQUEST;
bool cycle_energy_busy(void) {
    portENTER_CRITICAL(&mux);bool b=c.busy;portEXIT_CRITICAL(&mux);return b;
}
const char *cycle_energy_id(void) { static char id[17];portENTER_CRITICAL(&mux);memcpy(id,c.id,17);portEXIT_CRITICAL(&mux);return id; }
static void event(const char *kind,const char *id,const char *reason) {
    cJSON *o=cJSON_CreateObject(); if(!o)return;
    cJSON_AddStringToObject(o,"event",kind);cJSON_AddNumberToObject(o,"protocol",1);
    cJSON_AddStringToObject(o,"id",id);cJSON_AddStringToObject(o,"challenge",crypto_get_mode_challenge());
    cJSON_AddStringToObject(o,"reason",reason?reason:"");
    char *json=cJSON_PrintUnformatted(o);if(json){mqtt_app_publish_cycle(json);free(json);}cJSON_Delete(o);
}
static int nibble(char b) {
    if(b>='0'&&b<='9')return b-'0';
    if(b>='a'&&b<='f')return b-'a'+10;
    if(b>='A'&&b<='F')return b-'A'+10;
    return -1;
}
void cycle_energy_request(const char *hex,size_t len) {
    if(!hex||(len&1)||len<72||len>256)return;
    unsigned char raw[128],plain[93]={0},aad[8+sizeof(aad_topic)-1];
    for(size_t i=0;i<len/2;i++){int a=nibble(hex[2*i]),b=nibble(hex[2*i+1]);if(a<0||b<0)return;raw[i]=(a<<4)|b;}
    memcpy(aad,raw+28,8);memcpy(aad+8,aad_topic,sizeof(aad_topic)-1);
    if(crypto_decrypt_data(raw+36,len/2-36,aad,sizeof(aad),raw,raw+12,plain))return;
    if(strlen((char *)plain)!=len/2-36)return;
    /* START:<id16>:<cycles1..100>:<challenge32> or ABORT:<id16>:<challenge32> */
    char *text=(char *)plain,*id=text+6;
    bool start=!strncmp(text,"START:",6),abort=!strncmp(text,"ABORT:",6);
    if((!start&&!abort)||strlen(text)<55||text[22]!=':')return;
    for(unsigned i=0;i<16;i++)if(nibble(id[i])<0)return;
    char ident[17];memcpy(ident,id,16);ident[16]=0;
    unsigned cycles=0;char *challenge=text+23;
    if(start){
        char *p=challenge;if(*p<'0'||*p>'9')return;
        while(*p>='0'&&*p<='9'){cycles=cycles*10+(*p++-'0');if(cycles>100)return;}
        if(*p++!=':'||cycles<1)return;
        challenge=p;
    }
    if(strlen(challenge)!=32||memcmp(challenge,crypto_get_mode_challenge(),32))return;
    if(start&&(cycle_energy_busy()||hardware_is_unlocked())){event("error",ident,"Thiết bị đang bận hoặc chưa ở trạng thái OFF.");return;}
    crypto_reset_mode_challenge();
    if(start){
        portENTER_CRITICAL(&mux);memset(&c,0,sizeof(c));c.busy=true;c.target=cycles*2;c.aes=crypto_is_aes_enabled();
        memcpy(c.id,ident,17);c.armed=esp_timer_get_time();portEXIT_CRITICAL(&mux);
        event("ready",ident,NULL);ina219_cycle_wake();
    } else {
        portENTER_CRITICAL(&mux);
        bool match=c.busy&&!strcmp(c.id,ident);
        if(match){c.aborted=true;c.ended=true;c.end=esp_timer_get_time();}
        portEXIT_CRITICAL(&mux);
        if(match)ina219_cycle_wake();else event("idle",ident,NULL);
    }
}
void cycle_energy_receive(int64_t us) {
    bool wake=false;
    portENTER_CRITICAL(&mux);
    if(c.busy&&!c.active&&!c.ended){c.active=true;c.start=us;wake=true;}
    portEXIT_CRITICAL(&mux);if(wake)ina219_cycle_wake();
}
void cycle_energy_applied(const char *id,bool on,int64_t us) {
    portENTER_CRITICAL(&mux);
    if(c.busy&&c.active&&!c.ended){
        bool good=id&&strlen(id)==16&&c.count<c.target&&on==(c.count%2==0)&&crypto_is_aes_enabled()==c.aes;
        for(unsigned i=0;good&&i<c.count;i++)if(!strcmp(c.ids[i],id))good=false;
        if(good){memcpy(c.ids[c.count++],id,17);if(c.count==c.target){c.end=us;c.ended=true;}}
        else c.interference=true;
    }
    portEXIT_CRITICAL(&mux);
}
void cycle_energy_interference(void){portENTER_CRITICAL(&mux);if(c.busy)c.interference=true;portEXIT_CRITICAL(&mux);}
void cycle_energy_disconnected(void){portENTER_CRITICAL(&mux);if(c.busy){c.network_bad=true;c.aborted=true;c.ended=true;c.end=esp_timer_get_time();}portEXIT_CRITICAL(&mux);}
void cycle_energy_sample(int64_t us,esp_err_t err,float v,float ma,float w) {
    portENTER_CRITICAL(&mux);
    if(c.busy&&c.active&&us>=c.start&&(!c.ended||us<=c.end)){
        if(err!=ESP_OK||!isfinite(v)||!isfinite(ma)||!isfinite(w))c.errors++;
        else {
            int64_t gap=us-(c.samples?c.last:c.start);if(gap>c.max_gap)c.max_gap=gap;
            c.energy+=(c.samples?(c.last_w+w)*.5:w)*gap/1e6;
            c.vsum+=(c.samples?(c.last_v+v)*.5:v)*gap;c.isum+=(c.samples?(c.last_i+ma)*.5:ma)*gap;
            if(c.samples)c.covered+=gap;else c.first=us;
            c.last=us;c.last_w=w;c.last_v=v;c.last_i=ma;c.samples++;
        }
    }
    portEXIT_CRITICAL(&mux);
}
void cycle_energy_tick(void) {
    int64_t now=esp_timer_get_time();bool done=false;
    portENTER_CRITICAL(&mux);
    if(c.busy){
        if((!c.active&&now-c.armed>30000000)||(c.active&&now-c.start>600000000)){c.aborted=true;c.ended=true;c.end=now;}
        if(c.ended){finished=c;done=true;}
    }
    portEXIT_CRITICAL(&mux);if(!done)return;
    capture_t *f=&finished;
    int64_t duration=f->active?f->end-f->start:0;
    if(f->samples){int64_t gap=f->end-f->last;if(gap>f->max_gap)f->max_gap=gap;
        f->energy+=f->last_w*gap/1e6;f->vsum+=f->last_v*gap;f->isum+=f->last_i*gap;
    }else f->max_gap=duration;
    double power=duration>0?f->energy*1e6/duration:0,v=duration>0?f->vsum/duration:0,ma=duration>0?f->isum/duration:0;
    bool valid=!f->aborted&&!f->interference&&!f->network_bad&&f->count==f->target&&duration>=1000000&&
        f->samples>=30&&!f->errors&&f->max_gap<=100000&&f->covered>=duration*.9&&v>=4&&v<=5.5&&power>0;
    cJSON *o=cJSON_CreateObject();if(o){
        cJSON_AddStringToObject(o,"event","done");cJSON_AddNumberToObject(o,"protocol",1);cJSON_AddStringToObject(o,"id",f->id);
        cJSON_AddStringToObject(o,"challenge",crypto_get_mode_challenge());
        cJSON_AddBoolToObject(o,"aes",f->aes);cJSON_AddBoolToObject(o,"valid",valid);
        cJSON_AddBoolToObject(o,"aborted",f->aborted);cJSON_AddBoolToObject(o,"interference",f->interference);
        cJSON_AddBoolToObject(o,"network_bad",f->network_bad);cJSON_AddNumberToObject(o,"target_commands",f->target);
        cJSON_AddNumberToObject(o,"applied",f->count);cJSON_AddNumberToObject(o,"duration_us",duration);
        cJSON_AddNumberToObject(o,"samples",f->samples);cJSON_AddNumberToObject(o,"errors",f->errors);
        cJSON_AddNumberToObject(o,"max_gap_us",f->max_gap);cJSON_AddNumberToObject(o,"covered_us",f->covered);
        cJSON_AddNumberToObject(o,"cpu_mhz",esp_rom_get_cpu_ticks_per_us());
        cJSON_AddStringToObject(o,"idf_version",esp_get_idf_version());
#ifdef CONFIG_MBEDTLS_HARDWARE_AES
        cJSON_AddBoolToObject(o,"hardware_aes",true);
#else
        cJSON_AddBoolToObject(o,"hardware_aes",false);
#endif
        wifi_ps_type_t ps;int wifi_ps=esp_wifi_get_ps(&ps)==ESP_OK?(int)ps:-1;cJSON_AddNumberToObject(o,"wifi_ps",wifi_ps);
        const char *keys[]={"energy_j","mean_power_w","mean_voltage_v","mean_current_ma"};double values[]={f->energy,power,v,ma};
        for(unsigned i=0;i<4;i++){if(f->samples&&duration>0)cJSON_AddNumberToObject(o,keys[i],values[i]);else cJSON_AddNullToObject(o,keys[i]);}
        cJSON *ids=cJSON_AddArrayToObject(o,"command_ids");for(unsigned i=0;ids&&i<f->count;i++)cJSON_AddItemToArray(ids,cJSON_CreateString(f->ids[i]));
        char *json=cJSON_PrintUnformatted(o);if(json){mqtt_app_publish_cycle(json);free(json);}cJSON_Delete(o);
    }
    portENTER_CRITICAL(&mux);memset(&c,0,sizeof(c));portEXIT_CRITICAL(&mux);
}
