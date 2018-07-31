#!/bin/sh

echo 'building image that will be used has basis for scfs'
cd docker_pre_req_thesis
docker build -t pre_thesis_img .

echo 'building scfs image'
cd ..
docker build -t thesis_img .

cd test_images
docker build -t test_thesis_img .