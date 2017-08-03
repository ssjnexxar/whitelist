#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "whitelist.h"
#include "ipaddr.h"
#include <openssl/md5.h>

struct ip_list{
	ip_addr_t ip;
	struct ip_list *next;
};

struct whitelist_data{
	struct ip_list *IPV4;
	struct ip_list *IPV6;
	char *filename;
	bool init_md5;
	unsigned char md5_hash[MD5_DIGEST_LENGTH];
};

int ip_from_str(const char *str, ip_addr_t *addr);
ip_addr_t ip_from_4_bytes_be(char b[4]);
ip_addr_t ip_from_16_bytes_be(char b[16]);
int ip_is4(const ip_addr_t *addr);

/*FUNKCIA PRE VYTVORENIE LINEARNEHO ZOZNAMU*/

struct whitelist_data *whitelist_init(int *error_code, const char *filename){
	
	struct ip_list *head=NULL;
	struct whitelist_data *wlist;
	FILE *fp;
	char *line;
	size_t n=0;
	int c;
	int i=0;
	int cmp_ip;
	int cmp_ipv;
	
	fp=fopen(filename,"r");

	/*OSETRENIE OPEN ERRORU*/
	
	if (!fp){
		*error_code=WL_OPEN_FILE;
		return NULL;
	}
	
	line=malloc(1024);
	
	/*OSETRENIE MALLOC ERRORU*/
	
	if(line==NULL){
		*error_code=WL_FAIL_MEMORY;
		return NULL;
	}
	
	/*OSETRENIE MALLOC ERRORU*/
	
	wlist=(struct whitelist_data*)malloc(sizeof(struct whitelist_data));
	if(wlist==NULL){
		*error_code=WL_FAIL_MEMORY;
		return NULL;
	}
	
	/*PREBERANIE ZO SUBORU A VYTVARANIE LINEARNEHO ZOZNAMU*/
	
	while((c = fgetc(fp))!=EOF){
		n=0;
		line[n++]=(char)c;
		while((c = fgetc(fp))!='\n' && n!=1023){							/*PREBERANIE ZNAK PO ZNAKU AZ PO \n*/
			line[n++]=(char)c;												/*UKLADANIE ZNAKOV DO LINE*/
		}
		line[n]='\0';
		
		struct ip_list *tmp;
		tmp=(struct ip_list *)malloc(sizeof(struct ip_list));
		if(tmp==NULL){														/*OSETRENIE MALLOC ERRORU*/
				*error_code=WL_FAIL_MEMORY;		
				return NULL;
		}
		
		cmp_ip=ip_from_str(line, &tmp->ip);									/*OSETRENIE IP ERRORU*/
		
		if(cmp_ip==0){
			*error_code=WL_INVALID_IP;
			printf("Chyba nastala na %d riadku.", i);
			return NULL;
		}
		else if(cmp_ip==1){
		
			cmp_ipv=ip_is4(&tmp->ip);										/**ROZDELENIE IP ADRIES*/
			
			if(cmp_ipv==1){													/*IPV4*/
				if(head==NULL){							
					head=tmp;
					head->next=wlist->IPV4;
					wlist->IPV4=head;
					head->next=NULL;
				}
				else{									
					tmp->next=wlist->IPV4;
					wlist->IPV4=tmp;
					tmp->next=head;
					head=tmp;
				}
			}
			
			if(cmp_ipv==0){													/*IPV6*/
				if(head==NULL){							
					head=tmp;
					head->next=wlist->IPV6;
					wlist->IPV6=head;
					head->next=NULL;
				}
				else{									
					tmp->next=wlist->IPV6;
					wlist->IPV4=tmp;
					tmp->next=head;
					head=tmp;
				}
			}
		}
		i++;
	}
	fclose(fp);
	free(line);
	return wlist;
}

/*FUNKCIA PRE KONTROLU ZMENY SUBORU*/

int whitelist_reload(whitelist_data_t *data, const char *filename){
	
	unsigned char hash[MD5_DIGEST_LENGTH]
	char file_context[1024];
	int bytes;
	MD5_CTX mdContext;
	FILE *fp;
	
	if(!(fp=fopen(filename,"r")))
		return WL_OPEN_FILE;
	
	MD5_Init(&mdContext);
	while((bytes=fread(file_context, 1, 1024, fp))!=0)
		MD5_Update(&mdContext, file_context, bytes);
	
	MD5_Final(hash, &mdContext);
	fclose(fp);
	
	if(!data->init_md5){
		memcpy(data->md5_hash, hash, MD5_DIGEST_LENGTH);
		data->init_md5=true;
		return 
	}
	
	if(memcmp(data->md5_hash, hash, MD5_DIGEST_LENGHT)!=0){
		memcpy(data->md5_hash, hash, MD5_DIGEST_LENGHT);
		return
	}
	return WL_FILE_NOT_CHANGED;
	
}

/*FUNKCIA PRE VYHLADAVANIE ADRIES*/

bool whitelist_search_ip(whitelist_data_t *data, ip_addr_t *ip){
	
	int cmp, scmp;
	struct ip_list *tmp;
	
	cmp=ip_is4(ip);
	
	if(cmp==1)
		tmp=data->IPV4;
	else if(cmp==0)
		tmp=data->IPV6;

	while(tmp!=NULL){
		scmp=memcmp(&tmp->ip,ip, sizeof(ip_addr_t));									
		if(scmp==0)			
			return true;
		else
			tmp=tmp->next;
	}
	return false;
}
	
/*FUNKCIA PRE UVOLNOVANIE PAMATE*/

void whitelist_free(whitelist_data_t *data){
	
	struct ip_list *tmp4=data->IPV4, *tmp6=data->IPV6, *ne;
	
	while(tmp4!=NULL){
		ne=tmp4->next
		free(tmp4);
		tmp4=ne;
	}
	
	while(tmp6!=NULL){
		ne=tmp6->next
		free(tmp6);
		tmp6=ne;
	}
	free(data);
	data=NULL;
}

int main(){
	
	
	return 0;
}