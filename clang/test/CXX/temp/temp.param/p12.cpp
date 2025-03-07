// RUN: %clang_cc1 -fsyntax-only -verify %s
template<typename> struct Y1; // expected-note{{template is declared here}}
template<typename, int> struct Y2;

// C++ [temp.param]p12:
template<class T1,
         class T2 = int> // expected-note{{previous default template argument defined here}}
  class B3;
template<class T1, typename T2> class B3;
template<class T1,
         typename T2 = float> // expected-error{{template parameter redefines default argument}}
  class B3;

template<template<class, int> class,
         template<class> class = Y1> // expected-note{{previous default template argument defined here}}
  class B3t;

template<template<class, int> class, template<class> class> class B3t;

template<template<class, int> class,
         template<class> class = Y1> // expected-error{{template parameter redefines default argument}}
  class B3t;

template<int N,
         int M = 5> // expected-note{{previous default template argument defined here}}
  class B3n;

template<int N, int M> class B3n;

template<int N,
         int M = 7>  // expected-error{{template parameter redefines default argument}}
  class B3n;

// Check validity of default arguments
template<template<class, int> class =// expected-note {{template parameter is declared here}}
           Y1> // expected-error{{too many template arguments for class template 'Y1'}}
               // expected-note@-1 {{template template argument is incompatible}}
  class C1 {};

C1<> c1; // expected-note{{while checking a default template argument}}
