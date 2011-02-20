#include "rbt.h"

/*
 * from http://www.cs.auckland.ac.nz/software/AlgAnim/niemann/s_man.htm
 * Source code, when part of a software project, may be used freely without reference to the author
 */

#define compLT(a,b) (a < b)
#define compEQ(a,b) (a == b)

#define NIL &sentinel		/* all leafs are sentinels */
rbt_t sentinel = {
  NIL, NIL, 0, BLACK, 0
};
void rotateLeft (rbt_t ** root, rbt_t * x)
{

   /**************************
    *  rotate node x to left *
    **************************/
  rbt_t *y = x->right;

  /* establish x->right link */
  x->right = y->left;
  if (y->left != NIL)
    y->left->parent = x;

  /* establish y->parent link */
  if (y != NIL)
    y->parent = x->parent;
  if (x->parent) {
    if (x == x->parent->left)
      x->parent->left = y;

    else
      x->parent->right = y;
  } else {
    *root = y;
  }

  /* link x and y */
  y->left = x;
  if (x != NIL)
    x->parent = y;
}

void rotateRight (rbt_t ** root, rbt_t * x)
{

   /****************************
    *  rotate node x to right  *
    ****************************/
  rbt_t *y = x->left;

  /* establish x->left link */
  x->left = y->right;
  if (y->right != NIL)
    y->right->parent = x;

  /* establish y->parent link */
  if (y != NIL)
    y->parent = x->parent;
  if (x->parent) {
    if (x == x->parent->right)
      x->parent->right = y;

    else
      x->parent->left = y;
  } else {
    *root = y;
  }

  /* link x and y */
  y->right = x;
  if (x != NIL)
    x->parent = y;
}

void insertFixup (rbt_t ** root, rbt_t * x)
{

   /*************************************
    *  maintain Red-Black tree balance  *
    *  after inserting node x           *
    *************************************/

  /* check Red-Black properties */
  while (x != *root && x->parent->color == RED) {

    /* we have a violation */
    if (x->parent == x->parent->parent->left) {
      rbt_t *y = x->parent->parent->right;

      if (y->color == RED) {

	/* uncle is RED */
	x->parent->color = BLACK;
	y->color = BLACK;
	x->parent->parent->color = RED;
	x = x->parent->parent;
      } else {

	/* uncle is BLACK */
	if (x == x->parent->right) {

	  /* make x a left child */
	  x = x->parent;
	  rotateLeft (root, x);
	}

	/* recolor and rotate */
	x->parent->color = BLACK;
	x->parent->parent->color = RED;
	rotateRight (root, x->parent->parent);
      }
    } else {

      /* mirror image of above code */
      rbt_t *y = x->parent->parent->left;

      if (y->color == RED) {

	/* uncle is RED */
	x->parent->color = BLACK;
	y->color = BLACK;
	x->parent->parent->color = RED;
	x = x->parent->parent;
      } else {

	/* uncle is BLACK */
	if (x == x->parent->left) {
	  x = x->parent;
	  rotateRight (root, x);
	}
	x->parent->color = BLACK;
	x->parent->parent->color = RED;
	rotateLeft (root, x->parent->parent);
      }
    }
  }
  (*root)->color = BLACK;
}

void insertNode (rbt_t ** root, rbt_t * new)
{
  rbt_t *current, *parent;


   /***********************************************
    *  allocate node for data and insert in tree  *
    ***********************************************/

  /* find where node belongs */
  current = *root;
  parent = 0;
  while (current != NIL) {
    parent = current;
    current = compLT (new->data, current->data) ? current->left : current->right;
  }

  /* setup new node */
  new->parent = parent;
  new->left = NIL;
  new->right = NIL;
  new->color = RED;

  /* insert node in tree */
  if (parent) {
    if (compLT (new->data, parent->data))
      parent->left = new;

    else
      parent->right = new;
  } else {
    *root = new;
  }
  insertFixup (root, new);
}

void deleteFixup (rbt_t ** root, rbt_t * x)
{

   /*************************************
    *  maintain Red-Black tree balance  *
    *  after deleting node x            *
    *************************************/
  while (x != *root && x->color == BLACK) {
    if (x == x->parent->left) {
      rbt_t *w = x->parent->right;

      if (w->color == RED) {
	w->color = BLACK;
	x->parent->color = RED;
	rotateLeft (root, x->parent);
	w = x->parent->right;
      }
      if (w->left->color == BLACK && w->right->color == BLACK) {
	w->color = RED;
	x = x->parent;
      } else {
	if (w->right->color == BLACK) {
	  w->left->color = BLACK;
	  w->color = RED;
	  rotateRight (root, w);
	  w = x->parent->right;
	}
	w->color = x->parent->color;
	x->parent->color = BLACK;
	w->right->color = BLACK;
	rotateLeft (root, x->parent);
	x = *root;
      }
    } else {
      rbt_t *w = x->parent->left;

      if (w->color == RED) {
	w->color = BLACK;
	x->parent->color = RED;
	rotateRight (root, x->parent);
	w = x->parent->left;
      }
      if (w->right->color == BLACK && w->left->color == BLACK) {
	w->color = RED;
	x = x->parent;
      } else {
	if (w->left->color == BLACK) {
	  w->right->color = BLACK;
	  w->color = RED;
	  rotateLeft (root, w);
	  w = x->parent->left;
	}
	w->color = x->parent->color;
	x->parent->color = BLACK;
	w->left->color = BLACK;
	rotateRight (root, x->parent);
	x = *root;
      }
    }
  }
  x->color = BLACK;
}

void deleteNode (rbt_t ** root, rbt_t * z)
{
  rbt_t *x, *y;


   /*****************************
    *  delete node z from tree  *
    *****************************/
  if (!z || z == NIL)
    return;
  if (z->left == NIL || z->right == NIL) {

    /* y has a NIL node as a child */
    y = z;
  } else {

    /* find tree successor with a NIL node as a child */
    y = z->right;
    while (y->left != NIL)
      y = y->left;
  }

  /* x is y's only child */
  if (y->left != NIL)
    x = y->left;

  else
    x = y->right;

  /* remove y from the parent chain */
  x->parent = y->parent;
  if (y->parent)
    if (y == y->parent->left)
      y->parent->left = x;

    else
      y->parent->right = x;

  else
    *root = x;
  if (y->color == BLACK)
    deleteFixup (root, x);

  /* replace z with y */
  if (z != y) {
    y->parent = z->parent;
    y->color = z->color;
    y->left = z->left;
    y->right = z->right;
    if (z->parent) {
      if (y->parent->left == z) {
	y->parent->left = y;
      } else {
	y->parent->right = y;
      }
    };
    if (y->left->parent == z) {
      y->left->parent = y;
    }
    if (y->right->parent == z) {
      y->right->parent = y;
    }
    if (*root == z)
      *root = y;
  }
  z->parent = NULL;
  z->left = NIL;
  z->right = NIL;
  z->color = RED;
  z->data = 0;
}

void initRoot (rbt_t ** root)
{
  *root = NIL;
}

rbt_t *smallestNode (rbt_t ** root)
{
  rbt_t *n;

  if (*root == NIL)
    return NULL;
  n = *root;
  while (n->left != NIL)
    n = n->left;
  return n;
}
