/* Freestanding declarations for the compile-only Undercover harness.
 * This clang build has no host libc. The functions are not defined here
 * and are not a substitute for running the game. */
#pragma once
double sin(double);
double cos(double);
double tan(double);
double atan2(double, double);
double log2(double);
double sqrt(double);
float sqrtf(float);
double fabs(double);
float fabsf(float);
int isinf(double);
int isnan(double);
double floor(double);
double ceil(double);
double trunc(double);
double nearbyint(double);
double ldexp(double, int);
double fmod(double, double);
double remainder(double, double);
