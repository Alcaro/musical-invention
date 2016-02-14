musical-invention: *.c
	gcc -std=c99 *.c -omusical-invention -lnetfilter_queue -Wall -Werror -g -lnfnetlink
