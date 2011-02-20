#ifndef _RBT_H_
#define _RBT_H_

/*
 * from http://www.cs.auckland.ac.nz/software/AlgAnim/niemann/s_man.htm
 * Public domain.
 */ 
  
/* red-black tree */ 
  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef unsigned long long T;	/* type of item to be stored */


/* Red-Black tree description */ 
typedef enum { BLACK, RED } nodeColor;
typedef struct rbt {
  struct rbt *left;		/* left child */
  struct rbt *right;		/* right child */
  struct rbt *parent;		/* parent */
  nodeColor color;		/* node color (BLACK, RED) */
  T data;			/* data stored in node */
} rbt_t;
extern void insertNode (rbt_t ** root, rbt_t *);
extern void deleteNode (rbt_t **, rbt_t *);
extern void initRoot (rbt_t **);
extern rbt_t *smallestNode (rbt_t **);


#endif /* _RBT_H_ */
