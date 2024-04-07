  # LibcForPwn


### This repo is intedded for PWN and RE

You know how many times you don't have the correct libc version and you need to create a new vm? no more :)


Here is a list with all the relevent libc and ld in order to use it in `pwnint` or in `patchelf`

Every folder has the a diff version of libc


### TODO

Add more version as needed [Here is the list of all versions](https://sourceware.org/glibc/wiki/Glibc%20Timeline)

yo can add this downlaod files


use this links as version should be:


    #    libc6_{ver-number}-0ubuntu{seq_num}_arch.deb
    #     like this for exmaple:
    #     /libc6_2.34-0ubuntu1_amd64.deb

    #       wget https://launchpad.net/ubuntu/+archive/primary/+files//libc6_2.34-0ubuntu1_amd64.deb  
    #        wget https://launchpad.net/ubuntu/+archive/primary/+files//libc6_2.34-0ubuntu1_i386.deb                   

    #        then use 

    #      dpkg-deb -R libc6_2.34-0ubuntu1_amd64.deb .         

     #    and then in lib folder there is the package you just take the libc6.so.6 and us pwninit

      #  pwninit --bin ./format-string-1 --libc libc.so.6

       
