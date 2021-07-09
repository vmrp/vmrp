
#include "../include/other.h"
#include "proto.h"
#include "StringBuffer.h"


#define MAX(a,b) (((a)>(b))?(a):(b))

/*{

#define STRINGBUFFER_BLOCK 256

typedef struct StringBuffer_ {
   char* buffer;
   int bufferSize;
   int usedSize;
} StringBuffer;

}*/

StringBuffer* StringBuffer_new(char* data) {
   StringBuffer* this = (StringBuffer*) mr_mallocExt0(sizeof(StringBuffer));
   if (data != NULL) {
      int len = strlen2(data);
      this->bufferSize = MAX(STRINGBUFFER_BLOCK, len+1);
      this->buffer = mr_mallocExt0(this->bufferSize);
      this->usedSize = len;
      strncpy2(this->buffer, data, len+1);
   } else {
      this->bufferSize = STRINGBUFFER_BLOCK;
      this->buffer = mr_mallocExt0(this->bufferSize);
      this->usedSize = 0;
   }
   return this;
}

void StringBuffer_delete(StringBuffer* this) {
   mr_freeExt(this->buffer);
   mr_freeExt(this);
}

void StringBuffer_makeRoom(StringBuffer* this, int neededSize) {
   if (this->bufferSize <= neededSize) {
      int newSize = this->bufferSize * 2;
      if (newSize < neededSize)
         newSize += neededSize;
      this->buffer = mr_reallocExt(this->buffer, newSize + 1);
      this->bufferSize = newSize;
   }
}

void StringBuffer_addChar(StringBuffer* this, char ch) {
   StringBuffer_makeRoom(this, this->usedSize + 1);
   this->buffer[this->usedSize] = ch;
   this->usedSize++;
   this->buffer[this->usedSize] = '\0';
}

void StringBuffer_set(StringBuffer* this, const char* str) {
   int len = strlen2(str);
   StringBuffer_makeRoom(this, len+1);
   strncpy2(this->buffer, str, len+1);
   this->usedSize = len;
   this->buffer[this->usedSize] = '\0';
}

void StringBuffer_add(StringBuffer* this, char* str) {
   int len = strlen2(str);
   int end = this->usedSize;
   StringBuffer_makeRoom(this, this->usedSize + len+1);
   strncpy2(this->buffer + end, str, len+1);
   this->usedSize += len;
   this->buffer[this->usedSize] = '\0';
}

void StringBuffer_prepend(StringBuffer* this, char* str) {
   int len = strlen2(str);
   int end = this->usedSize;
   int i;
   StringBuffer_makeRoom(this, this->usedSize + len+1);
   for (i = end; i >= 0; i--)
      this->buffer[i+len] = this->buffer[i];
   strncpy2(this->buffer, str, len);
   this->usedSize += len;
}

void StringBuffer_addAll(StringBuffer* this, int n, ...) {
   int i;
   char* s;
   va_list ap;
   va_start(ap, n);
   for (i = 0; i < n; i++) {
      s = va_arg(ap, char*);
      StringBuffer_add(this, s);
   }
   va_end(ap);
}

void StringBuffer_printf(StringBuffer* this, char* format, ...) {
   va_list ap;
   int n, size = 100;
   while (1) {
      StringBuffer_makeRoom(this, size + 1);
      va_start(ap, format);
      n = vsnprintf_(this->buffer, size, format, ap);
      va_end(ap);
      if (n > -1 && n < size) {
         this->usedSize = n;
         return;
      }
      size *= 2;
   }
}

void StringBuffer_addPrintf(StringBuffer* this, char* format, ...) {
   va_list ap;
   int n, size = 100;
   int end = this->usedSize;
   while (1) {
      StringBuffer_makeRoom(this, end + size + 1);
      va_start(ap, format);
      n = vsnprintf_(this->buffer + end, size, format, ap);
      va_end(ap);
      if (n > -1 && n < size) {
         this->usedSize = end + n;
         return;
      }
      size *= 2;
   }
}

char* StringBuffer_getCopy(StringBuffer* this) {
   char* result = mr_mallocExt0(this->bufferSize+1);
   strncpy2(result, this->buffer, this->usedSize);
   result[this->usedSize] = '\0';
   return result;
}

char* StringBuffer_getRef(StringBuffer* this) {
   return this->buffer;
}

char* StringBuffer_getBuffer(StringBuffer* this) {
   char* result = this->buffer;
   this->bufferSize = STRINGBUFFER_BLOCK;
   this->buffer = mr_mallocExt0(this->bufferSize);
   this->usedSize = 0;
   return result;
}

void StringBuffer_prune(StringBuffer* this) {
   this->usedSize = 0;
   this->buffer[0] = '\0';
}
