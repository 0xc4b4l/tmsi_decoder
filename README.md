# tmsi_decoder
An EAP-SIM/AKA TMSI (Temporary Mobile Subscriber Identity) decoder routine in PERL

This is a basic PERL program which takes the TMSI (or also known as a pseduonym) and decodes it into the actual IMSI
The decoding standard is based on 3GPP S3-020654
Note that the encryption key must be known in order to have this work, without the correct encryption key on the 3GPP-AAA server, this will not work

Just call the program
$ ./decoder-new.pl [TMSI] 

and the output will be the actual IMSI value
