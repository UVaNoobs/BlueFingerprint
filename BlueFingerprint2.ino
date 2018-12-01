
#include <aes_dec.h>
#include <aes_types.h>
#include <keysize_descriptor.h>
#include <bcal-cmac.h>
#include <bcal_aes192.h>
#include <bcal-basic.h>
#include <bcal_aes128.h>
#include <memxor.h>
#include <AESLib.h>
#include <aes_sbox.h>
#include <blockcipher_descriptor.h>
#include <aes_enc.h>
#include <gf256mul.h>
#include <bcal-cbc.h>
#include <aes_keyschedule.h>
#include <aes.h>
#include <aes128_dec.h>
#include <aes256_enc.h>
#include <aes_invsbox.h>
#include <bcal-ofb.h>
#include <bcal_aes256.h>
#include <aes192_dec.h>
#include <aes192_enc.h>
#include <aes256_dec.h>
#include <aes128_enc.h>



void setup() {
  Serial.begin(57600);
  for(int i=0; i<10;i++){
    //necesita 32 elementos en la clave
  uint8_t key[] = {110,15,26,213,44,225,116,71,83,96,10,181,172,173,194,165,146,127,138,159,240,29,22,23,24,25,26,27,28,29,30,31};
  char data[] = "1234";
  //aes256_enc_single(key, data);
  aes256_enc_single(key, data);   
  Serial.print(i);
  Serial.print("- encrypted:");
  Serial.println(data);
  aes256_dec_single(key, data);
  Serial.print(i);
  Serial.print("- decrypted:");
  Serial.println(data);
  }
   
  
}

void loop() {

  
}
