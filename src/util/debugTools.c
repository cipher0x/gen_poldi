#include "debugTools.h"
#include <string.h>

void sprintSEXP_Ed25519(gcry_sexp_t in, char *rt, size_t strSize)
{
  size_t rsaBuff_n;
  char *rsaBuff;
  char btmpStr[10];
  char tmpStr[10];

  //allocate buffer memory
  rsaBuff_n = gcry_sexp_sprint(in, GCRYSEXP_FMT_CANON, NULL, 0);
  rsaBuff = calloc(1, rsaBuff_n);
  if(!rsaBuff){printf("Error Allocating Dynamic Memory\n");}
  //printf("Buffer Size: %zu\n", rsaBuff_n);
  gcry_sexp_sprint(in, GCRYSEXP_FMT_CANON, rsaBuff, rsaBuff_n);

  int k = 0;
  char strByteSize[10];
  int byteSize = 0;
  int val;

  for(int i=0; i != rsaBuff_n; i++) {
    if(rsaBuff[i] == '1')
      {
	k = i + 1;
	strByteSize[0] = 0;
	byteSize = 0;

	if(k <= rsaBuff_n)
	  {
	  if(rsaBuff[k] == ':')
	  {
	    //read 1
	    addCToStr(rsaBuff[i], rt, strSize);
	    i++;

	    //read :
	    addCToStr(rsaBuff[i], rt, strSize);
	    i++;

	    //read control char
	    addCToStr(rsaBuff[i], rt, strSize);
	    i++;

	    //read in byte size :
	    while(rsaBuff[i] != ':')
	    {
	      addCToStr(rsaBuff[i], strByteSize, 10);
	      addCToStr(rsaBuff[i], rt, strSize);
	      i++;
	    }//while

	    byteSize = atoi(strByteSize);

	    //read in second :
	    addCToStr(rsaBuff[i], rt, strSize);
	    i++;

	    //iterate through each byte
	    for(int j=0; j != byteSize; j++) {

	      val = (unsigned char)rsaBuff[i];
	      sprintf(tmpStr,"%X",val);

	      //need traling zero
	      if(strlen(tmpStr) < 2) {
		strcpy(btmpStr, tmpStr);

		tmpStr[0]='0';
		tmpStr[1]=0;
		strcat(tmpStr,btmpStr);
	      }
	      strcat(rt, tmpStr);
	      i++;
	       }//for
       }//if
     }//if
   }//if key type

    addCToStr(rsaBuff[i], rt, strSize);
  }//for
}//sprintSEXP_Ed25519



void addCToStr(char c, char *in, size_t maxStrLn)
{
  int endOfStr = strlen(in);
  if(endOfStr+1 >= maxStrLn){return;}

  in[endOfStr] = c;
  endOfStr++;
  in[endOfStr] = 0;
}
