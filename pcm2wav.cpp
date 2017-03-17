
#include <stdio.h>
#include <string.h>
//#include <inttypes.h>
#include "pcm2wav.h"


//define wav head  44byte

static struct RIFFHEAD    //12byte
{
	char  riff[4];
	int32_t length;
	char 	wave[4];
} headr;
/*
static struct CHUNK   
{
	char name[4];
	int32_t size;
} headc;
*/
static struct WAVEFMT/*format*/    //24byte
{
	char fmt[4];      /* "fmt " */
	int32_t fmtsize;    /*0x10*/
	int16_t tag;        /*format tag. 1=PCM*/
	int16_t channel;    /*1*/
	int32_t smplrate;
	int32_t bytescnd;   /*average bytes per second*/
	int16_t align;      /*block alignment, in bytes*/
	int16_t nbits;      /*specific to PCM format*/
}headf;

/*static struct WAVEFACT   //12byte
{
	char fact[4];
	char temp[8];
}headfact;*/

static struct WAVEDATA /*data*/    //8byte
{
	char data[4];    /* "data" */
	int32_t datasize;     //data size,based on the pcapfile
}headw;

void pcm2wav(const char *file, const unsigned char *buffer, int32_t size, int16_t channel, int32_t smplrate, int32_t bytescnd,int16_t align, int16_t nbits)
{
	FILE *fp;
	int32_t wsize,sz=0;
	fp = fopen(file, "wb");
	//fp = fopen("input.pcm","wb");
	if(fp == NULL)
	{
		printf("Can't open %s for writing.", file);
		return;
	}
	/*header*///write the wav head into pcmfile
	strncpy(headr.riff,"RIFF",4);
	//write_i32_le (&headr.length, 4+sizeof(struct WAVEFMT)+sizeof(struct WAVEDATA)+size);
	write_i32_le (&headr.length,size+44-8);
	strncpy(headr.wave,"WAVE",4);
	fwrite(&headr,sizeof(struct RIFFHEAD),1,fp);
	
	strncpy(headf.fmt, "fmt ",4);
	write_i32_le (&headf.fmtsize,  sizeof(struct WAVEFMT)-8);
	write_i16_le (&headf.tag,      1);
	write_i16_le (&headf.channel,  channel);
	write_i32_le (&headf.smplrate, smplrate);      //samplerate:8KHZ or 16KHZ
	write_i32_le (&headf.bytescnd, bytescnd);    // nbit*1000
	write_i16_le (&headf.align,    align);         //nbit/8
	write_i16_le (&headf.nbits,    nbits);        //nbit
	fwrite(&headf,sizeof(struct WAVEFMT),1,fp);

	//strncpy(headfact.fact,"fact",4);
//	strncpy(headfact.temp,"",8);
//	fwrite(&headf,sizeof(struct WAVEFACT),1,fp);
	
	strncpy(headw.data,"data",4);
	write_i32_le (&headw.datasize, size );
	fwrite(&headw,sizeof(struct WAVEDATA),1,fp);
	
	for(wsize=0;wsize<size;wsize+=sz)
	{
		sz= (size-wsize>MEMORYCACHE)? MEMORYCACHE:(size-wsize);
		if(fwrite((buffer+(wsize)),(size_t)sz,1,fp)!=1)
		{
			printf("%s: write error!", file);
			return;
		}
	}
	fclose(fp);

}
/*
 *	write_i16_le
 *	Write a little-endian 16-bit signed integer to memory area
 *	pointed to by <ptr>.
 */
void write_i16_le (void *ptr, int16_t val)
{
  ((uint8_t *) ptr)[0] = val;
  ((uint8_t *) ptr)[1] = val >> 8;
}

/*
 *	write_i32_le
 *	Write a little-endian 32-bit signed integer to memory area
 *	pointed to by <ptr>.
 */
void write_i32_le (void *ptr, int32_t val)
{
  ((uint8_t *) ptr)[0] = val;
  ((uint8_t *) ptr)[1] = val >> 8;
  ((uint8_t *) ptr)[2] = val >> 16;
  ((uint8_t *) ptr)[3] = val >> 24;
}

/*
 *	peek_i16_le
 *	Read a little-endian 16-bit signed integer from memory area
 *	pointed to by <ptr>.
 */
int16_t peek_i16_le (const void *ptr)
{
  return ((const uint8_t *) ptr)[0]
      | (((const uint8_t *) ptr)[1] << 8);
}

/*
 *	peek_u16_le
 *	Read a little-endian 16-bit unsigned integer from memory area
 *	pointed to by <ptr>.
 */
uint16_t peek_u16_le (const void *ptr)
{
  return ((const uint8_t *) ptr)[0]
      | (((const uint8_t *) ptr)[1] << 8);
}

/*
 *	peek_i32_le
 *	Read a little-endian 32-bit signed integer from memory area
 *	pointed to by <ptr>.
 */
int32_t peek_i32_le (const void *ptr)
{
  return    ((const uint8_t *) ptr)[0]
   | ((uint16_t) ((const uint8_t *) ptr)[1] << 8)
   | ((int32_t) ((const uint8_t *) ptr)[2] << 16)
   | ((int32_t) ((const uint8_t *) ptr)[3] << 24);
}







