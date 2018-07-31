#!/bin/sh
mkdir -p bin
javac -encoding utf8 -d bin -cp .:./lib/*.jar:../../../lib/HomomorphicAuthenticationLibrary.jar `find . -name "*.java"`
#java -cp bin:lib/*.jar:../../../lib/*.jar storage_integrity_verifier.gui.FrameProofVerify
