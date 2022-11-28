#!/usr/sh

protoc --prost_out=proto --prost_opt=file_descriptor_set --tonic_out=proto example.proto
