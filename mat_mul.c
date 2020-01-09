
//SADECE a_x ÇARPIMI KULLANILDI. DÝÐER ÇARPIM DENEME AMAÇLI EKLENDÝ.


#include "mat_mul.h"
#include <stdint.h>
#include <stdlib.h>
void mul_a_x(int *a, int *out, int *s, int n, int n1, int n_bar) {

	int i, j, k;

	int l = n % 4;
	int z = 0;

	for (i = 0; i < n - l; i += 4) {
		for (k = 0; k < n_bar; k++) {
			int sum[4] = { 0 };
			for (j = 0; j < n1; j++) {
				int sp = s[k*n1 + j];

				sum[0] += a[0 * (n1)+j + z] * sp;
				sum[1] += a[1 * (n1)+j + z] * sp;
				sum[2] += a[2 * (n1)+j + z] * sp;
				sum[3] += a[3 * (n1)+j + z] * sp;

			}

			out[(i + 0)*n_bar + k] += sum[0];
			out[(i + 2)*n_bar + k] += sum[2];
			out[(i + 1)*n_bar + k] += sum[1];
			out[(i + 3)*n_bar + k] += sum[3];
		}
		z += (n1) * 4;
	}

	if (n % 4 != 0) {
		for (int t = 0; t < l*n_bar; t += n_bar) {
			for (k = 0; k < n_bar; k++) {
				int sum[1] = { 0 };
				for (j = 0; j < n1; j++) {
					int sp = s[k*n1 + j];
					sum[0] += a[0 * n1 + j + z] * sp;
				}
				out[i*n_bar + k + t] += sum[0];
			}
			z += n1;
		}
	}
}

void mul_a_x2(int *pk, int *out, int *sk, int n, int n1, int n_bar) {

	int l = n1 % 4;
	int z = 0;
	int i, j, k;
	int *pk_t;

	pk_t = malloc(n*n1 *sizeof(int));

	for (i = 0; i < n; i++) {
		for (k = 0; k < n1; k++) {

			pk_t[k*n + i] = pk[i*n1 + k];


		}
	}

	for (i = 0; i < n1 - l; i += 4) {
		for (k = 0; k < n_bar; k++) {
			int sum[4] = { 0 };
			for (j = 0; j < n; j++) {
				int sp = sk[k*n + i];
				sum[0] += pk_t[(0) * (n)+j + z] * sp;
				sum[1] += pk_t[(1) * (n)+j + z] * sp;
				sum[2] += pk_t[(2) * (n)+j + z] * sp;
				sum[3] += pk_t[(3) * (n)+j + z] * sp;

			}

			/*out[(i + 0)*n_bar + k] += sum[0];
			out[(i + 1)*n_bar + k] += sum[1];
			out[(i + 2)*n_bar + k] += sum[2];
			out[(i + 3)*n_bar + k] += sum[3];*/

			out[k*n + (i + 0)] += sum[0];
			out[k*n + (i + 1)] += sum[1];
			out[k*n + (i + 2)] += sum[2];
			out[k*n + (i + 3)] += sum[3];


		}
		z += (n) * 4;
	}

	if (n1 % 4 != 0) {
		for (int t = 0; t < l*n_bar; t += n_bar) {
			for (k = 0; k < n_bar; k++) {
				int sum[1] = { 0 };
				for (j = 0; j < n; j++) {
					int sp = sk[k*n + j];
					sum[0] += pk_t[0 * n + j + z] * sp;
				}
				out[i*n_bar + k + t] += sum[0];
			}
			z += n;
		}
	}

	free(pk_t);

}