##
# saml_signer
#
# @file
# @version 0.1

CC = gcc
CFLAGS = -fPIC -Wall -O2

XMLSEC_CFLAGS := $(shell pkg-config --cflags xmlsec1-openssl libxml-2.0)
XMLSEC_LIBS   := $(shell pkg-config --libs xmlsec1-openssl libxml-2.0)

LIB_NAME = libsaml_signer.so
SRC = saml_signer.c
OBJ = $(SRC:.c=.o)

all: $(LIB_NAME)

$(LIB_NAME): $(OBJ)
	$(CC) -shared -o $@ $^ $(XMLSEC_LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(XMLSEC_CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(LIB_NAME)

.PHONY: all clean

# end
