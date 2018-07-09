# # # # # # #
# Makefile for assignment 2
#
# created May 2018
# Matt Farrugia <matt.farrugia@unimelb.edu.au>
#

CC     = gcc
CFLAGS = -Wall
C2Flags = -lssl -lcrypto
# modify the flags here ^
EXE    = certcheck
OBJ    = certcheck.o certificate_validation_operations.o

# add any new object files here ^

# top (default) target
all: $(EXE)

# how to link executable
$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ) $(C2Flags)

# other dependencies
certcheck.o: certificate_validation_operations.h
certificate_validation_operations.o: certificate_validation_operations.h

# ^ add any new dependencies here (for example if you add new modules)


# phony targets (these targets do not represent actual files)
.PHONY: clean cleanly all CLEAN

# `make clean` to remove all object and executable files
# `make CLEAN` to remove all object files
# `make cleanly` to `make` then immediately remove object files (inefficient)
clean:
	rm -f $(EXE) $(OBJ)
CLEAN: clean
	rm -f $(OBJ)
cleanly: all clean
