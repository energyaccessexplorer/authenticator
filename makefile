RW_URL ?= "https://api.resourcewatch.org"
EAE_URL ?= "http://eae.localhost/api"
CALLBACK_URL ?= "http://eae.localhost/tool"
APP_NAME ?= "EAE_DEV"
AUTHENTICATOR_PSK ?= "derp....derp....derp....derp...."
SOCKET ?= "/tmp/authenticator.sock"

default: build run

run:
	@ \
	RW_URL=${RW_URL} \
	EAE_URL=${EAE_URL} \
	APP_NAME=${APP_NAME} \
	CALLBACK_URL=${CALLBACK_URL} \
	AUTHENTICATOR_PSK=${AUTHENTICATOR_PSK} \
	SOCKET=${SOCKET} \
	./authenticator

build: clean
	@ go fmt
	@ go build

clean:
	@ rm -f authenticator
