
/*
 * pcm2wav.h
 *
 *  Created on: Oct 3, 2011
 *      Author: lithium
 */

#ifndef PCM2WAV_H_
#define PCM2WAV_H_

#define MEMORYCACHE  (0x8000L)

typedef signed char int8_t; 
typedef short int int16_t;
typedef  int  int32_t;
typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;


void pcm2wav(char *file, char *buffer, int32_t size, int16_t channel, int32_t smplrate, int32_t bytescnd,int16_t align, int16_t nbits);
void write_i16_le (void *ptr, int16_t val);
void write_i32_le (void *ptr, int32_t val);
int16_t peek_i16_le (const void *ptr);
uint16_t peek_u16_le (const void *ptr);
int32_t peek_i32_le (const void *ptr);


#endif /* PCAP2WAV_H_ */
