#include <stdio.h>
#include <helper_functions.h>
#include <helper_cuda.h> 

#define BLOCK_SIZE 256 
#define MAX_KERNELS 16

typedef struct {
	int myPlainText;
	int myD;
	int myIsDValid; 

}IsPlainTxt;

__device__ bool isCongruent(int aNumA, int aNumB, int aModN) { 
	return aNumA % aModN == aNumB % aModN;
}
__global__ void testKeys(IsPlainTxt* aPlainTxtArr, int aXWindowSize, int aYWindowSize, int aXOffset, int aYOffset, int aN, int aCipherText) {

	// column value 
	int theXIdx = blockIdx.x;
	
	// row value
	int theYIdx = threadIdx.x + blockIdx.y * blockDim.x;

	int theD = theXIdx + aXOffset;
	int thePlainText = theYIdx +aYOffset;  
	int i = (aXWindowSize * theYIdx) + theXIdx;

	bool thePlainTextAndDCheck = (thePlainText < aCipherText) && (theD < aN); 
	bool theXYIdxCheck = i < (aXWindowSize * aYWindowSize);

	if (thePlainTextAndDCheck && theXYIdxCheck) {

		if (isCongruent(thePlainText, pow(aCipherText, theD), aN)) aPlainTxtArr[i] = { thePlainText, theD, 1 };
		else aPlainTxtArr[i] = { thePlainText, theD, 0 };

	}
	

}

void errorCatcher( cudaError_t aError) { 
	if (aError != cudaSuccess) {
		printf("cudaMalloc failed! Error: %s\n", cudaGetErrorString(aError));
		exit(EXIT_FAILURE);
	}
}

IsPlainTxt* getKeys( int aXWindowSize /*n*/, int aYWindowSize/*ciphertext*/, int aCipherText, int aN, int aXOffset, int aYOffset) {

		IsPlainTxt* theIsPlainTxtArr;
		IsPlainTxt* CUDA_theIsPlainTxtArr;
		
		int theArrSize = aXWindowSize * aYWindowSize; 
		int theArrByteSize = theArrSize * sizeof(IsPlainTxt);

		theIsPlainTxtArr=(IsPlainTxt*)malloc(theArrByteSize); 
		errorCatcher(cudaMalloc((void**)&CUDA_theIsPlainTxtArr, theArrByteSize));
		
		int theNumThreads = BLOCK_SIZE; 
		
		int theNumBlockX = aXWindowSize;
		int theNumBlockY = (aYWindowSize - 1 + theNumThreads) / theNumThreads;
		
		/*
		testKeys << <dim3(theNumBlockX, theNumBlockY), theNumThreads >> > (CUDA_theIsPlainTxtArr, aCipherText, aN, 0);
		cudaMemcpy(theIsPlainTxtArr, CUDA_theIsPlainTxtArr, theArrByteSize, cudaMemcpyDeviceToHost);
		*/
		
		int theNumBlockYReduced = (theNumBlockY - 1 + MAX_KERNELS) / MAX_KERNELS;
		int theSegmentSize = theNumBlockX*theNumBlockYReduced*theNumThreads; 
		int thePlainTextOffset = theSegmentSize/theNumBlockX;
		
		


		cudaStream_t theStreams[MAX_KERNELS];

		for (int i = 0; i < MAX_KERNELS; ++i) cudaStreamCreate(&theStreams[i]);
		

		for (int i = 0; i < MAX_KERNELS; ++i) {

			int theTotalOffset = i * theSegmentSize;  

			int theYOffset = (thePlainTextOffset * i) + aYOffset;

			testKeys <<< dim3(theNumBlockX, theNumBlockYReduced), theNumThreads, 0, theStreams[i] >>>
				(CUDA_theIsPlainTxtArr+theTotalOffset, aXWindowSize, aYWindowSize, aXOffset, theYOffset , aN, aCipherText);
		} 

		
		int theSegmentByteSize = theSegmentSize * sizeof(IsPlainTxt); 
		int theRemainingBytes =  theArrByteSize - ((MAX_KERNELS - 1) * theSegmentByteSize); 
		if ((MAX_KERNELS - 1) * theSegmentSize > theArrSize) theRemainingBytes =( theArrSize - (theArrSize / theSegmentSize) * theSegmentSize) * sizeof(IsPlainTxt);


		for (int i = 0; i < MAX_KERNELS; ++i) {

			int theOffset = i * theSegmentSize; 

			if (theOffset > theArrSize) { 
				theOffset -= theSegmentSize;
				cudaMemcpyAsync(theIsPlainTxtArr + theOffset, CUDA_theIsPlainTxtArr + theOffset, theRemainingBytes, cudaMemcpyDeviceToHost, theStreams[i]);
				break;
			}

			int theTransferByteSize = (i != MAX_KERNELS - 1) ? theSegmentByteSize : theRemainingBytes;
			cudaMemcpyAsync(theIsPlainTxtArr + theOffset, CUDA_theIsPlainTxtArr + theOffset, theTransferByteSize, cudaMemcpyDeviceToHost, theStreams[i]);
		
		}

		for (int i = 0; i < MAX_KERNELS; ++i) cudaStreamSynchronize(theStreams[i]);

		for (int i = 0; i < MAX_KERNELS; ++i) cudaStreamDestroy(theStreams[i]);
		
		cudaFree(CUDA_theIsPlainTxtArr);
		//errorCatcher(cudaFree(CUDA_theIsPlainTxtArr));
		
		return theIsPlainTxtArr;
		


}

int main()
{  
	int theCipherText= 1000000; 
	int aN = 7;
	int aXWindowSize = 3; 
	int aYWindowSize = 500000;
	int aStopConditionY =(theCipherText%aYWindowSize)	? theCipherText	+ (aYWindowSize - (theCipherText % aYWindowSize)) : theCipherText;
	int aStopConditionX =(aN%aXWindowSize!=0)			? aN			+ (aXWindowSize - (aN			 % aXWindowSize)) : aN;
	for (int x = 0; x < aStopConditionX; x += aXWindowSize) {
		for (int y = 0; y < aStopConditionY; y += aYWindowSize) {
			
			IsPlainTxt* theArr = getKeys(aXWindowSize, aYWindowSize, theCipherText, aN, x, y);

			for (int j = 0; j < aYWindowSize; j++) {
				for (int k = 0; k < aXWindowSize; k++) {

					IsPlainTxt theTempStruct = theArr[(j * aXWindowSize) + k];

					printf("{%d, %d, %c}, ",
						theTempStruct.myPlainText,
						theTempStruct.myD,
						theTempStruct.myIsDValid ? 'T' : 'F');
				}
				printf("\n");
			}

			free(theArr);

		}
	}
	
	return 0;
} 

/*
typedef struct {
	int my_d_pos;
	int my_phi_n;
	int my_d;
}GCD_Tuple;


__device__  int gcd(int a_a, int a_b) {
	while (a_b != 0) {
		int the_temp = a_b;
		a_b = a_a % a_b;
		a_a = the_temp;
	}
	return a_a;
}

__global__ void calculate_gcds_via_tuples(GCD_Tuple* a_tuple_arr, int* the_d_arr, int the_d_arr_size) {

	
		//======[METHODOLOGY]======

		//1. Transfer the tuple to shared memory first

		//2. Calculate the given GCD based on the recieved tuple
	
		//3. if GCD(a,b)==1, then place a into the d array as a valid value of d

		//4. Otherwise place -1 as an invalid tuple

		//======[EXAMPLE]======

		//1. GCD_Tuple the_example {3 + 1, 3, 1} --> {relative index + d, phi(n), d};

		//2. the_d_arr[3+1] = 1 since gcd(1,3)==1;

	

__shared__ GCD_Tuple the_tuple_buffer[BLOCK_SIZE];

int i = blockDim.x * blockIdx.x + threadIdx.x;
//int the_thread_idx = threadIdx.x;

if (i < the_d_arr_size) {
	
	//the_tuple_buffer[the_thread_idx] = a_tuple_arr[i];
	//__syncthreads();


	//int the_gcd= gcd(the_tuple_buffer[the_thread_idx].my_d, the_tuple_buffer[the_thread_idx].my_phi_n);
	//if (the_gcd == 1) the_d_arr[the_tuple_buffer[the_thread_idx].my_d_pos] = the_tuple_buffer[the_thread_idx].my_d;
	//else the_d_arr[the_tuple_buffer[the_thread_idx].my_d_pos] = -1;
	
	int the_gcd = gcd(a_tuple_arr[i].my_d, a_tuple_arr[i].my_phi_n);
	if (the_gcd == 1) the_d_arr[a_tuple_arr[i].my_d_pos] = a_tuple_arr[i].my_d;
	else the_d_arr[a_tuple_arr[i].my_d_pos] = -1;


}

}


__global__ void calculate_d_tuples_2(GCD_Tuple* a_tuple_arr, int a_n_value) {
	
		//======[METHODOLOGY]======

		//1. blockIdx.x + 1 == phi(n) --> phi(n) <= n

		//2. threadIdx.x == d  --> d < phi(n)

		//	(threadIdx.x + blockDim.x*blockIdx.y is for when # of combinations exceed BLOCK_SIZE)

		//3. Now calculate relative_idx=[n(n+1) / 2] - 1 to get the beginning index to start filling in the combinations for the specific phi(n)

		//	[n(n+1)/2] is basically like n factorial, except with addition, i.e, 4+3+2+1 = 4(4+1)/2 = 10

		//4. Now insert the tuple at [relative_idx + the_d] with the [relative_idx + the_d], d and phi_n for further parallel calculation

		//======[EXAMPLE]======

		//1. n = 6

		//2. phi(n) = 1,2,3,4,5,6

		//3. d = 0,1,2,3,4,5

		//4. a_tuple_arr	=	[	0 gcd(0,1),
		//						1 gcd(0,2),  2  gcd(1,2)
		//						3 gcd(0,3),  4  gcd(1,3), 5 gcd(2,3)
		//						6 gcd(0,4),  7  gcd(1,4), 8 gcd(2,4),   9  gcd(3,4)
		//						10 gcd(0,5), 11 gcd(1,5), 12  gcd(2,5), 13 gcd(3,5), 14 gcd(4,5)
		//						15 gcd(0,6), 16 gcd(1,6), 17 gcd(2,6),  18 gcd(3,6), 19 gcd(4,6), 20 gcd(5,6) ]

	
	int the_phi_n = blockIdx.x + 1;
	int the_d = threadIdx.x + blockDim.x * blockIdx.y;

	if (the_phi_n <= a_n_value && the_d < the_phi_n) {
		int the_relative_idx = ((the_phi_n * (the_phi_n + 1)) / 2) - the_phi_n;
		a_tuple_arr[the_relative_idx + the_d] = { the_relative_idx + the_d , the_phi_n , the_d };
	}
}


int* calculate_ds_tuple(int the_n) {
	int* the_d_array;
	int* the_cuda_d_array;
	GCD_Tuple* the_cuda_tuple_array;

	int the_d_array_size = (the_n * (the_n + 1)) / 2;

	int the_d_array_byte_size = the_d_array_size * sizeof(int);

	int the_cuda_tuple_array_byte_size = the_d_array_size * sizeof(int);

	cudaMalloc((void**)&the_cuda_d_array, the_d_array_byte_size);
	cudaMalloc((void**)&the_cuda_tuple_array, the_cuda_tuple_array_byte_size);
	the_d_array = (int*)malloc(the_d_array_byte_size);

	int the_thread_num_a = BLOCK_SIZE;
	int the_block_num_a_x = the_n;
	// if phi(n)>BLOCK_SIZE, we will need an additional row of blocks more combinations of gcd(d, phi(n)); 
	// Example --> gcd(256, 257) is beyond BLOCK_SIZE=256, so we need to create one more row of blocks.
	int the_block_num_a_y = (the_n + the_thread_num_a - 1) / the_thread_num_a;

	calculate_d_tuples_2 << <dim3(the_block_num_a_x, the_block_num_a_y), the_thread_num_a >> > (the_cuda_tuple_array, the_n);

	int the_thread_num_b = the_d_array_size > BLOCK_SIZE ? BLOCK_SIZE : the_d_array_size;// Emulate Ceiling Division To Get Enough Blocks
	int the_block_num_b = the_d_array_size > BLOCK_SIZE ? (the_d_array_size + BLOCK_SIZE - 1) / BLOCK_SIZE : 1;
	calculate_gcds_via_tuples << <the_block_num_b, the_thread_num_b >> > (the_cuda_tuple_array, the_cuda_d_array, the_d_array_size);

	cudaMemcpy(the_d_array, the_cuda_d_array, the_d_array_byte_size, cudaMemcpyDeviceToHost);

	cudaFree(the_cuda_d_array);
	cudaFree(the_cuda_tuple_array);

	return the_d_array;
}




*/


/*
	======[OLD IMPLEMENTATION]======

	1. Uses o(2n) time complexity, because the while loops of gcd() are sequential w/ for loops.

	2. New Implementation is o(n) since there are no more for loops.

	======[OLD IMPLEMENTATION]======

		__global__ void calculate_d_tuples(GCD_Tuple* a_tuple_arr, int a_n_value) {

			int i = blockDim.x * blockIdx.x + threadIdx.x + 1;
			if (i <= a_n_value) {
				int the_relative_idx = ((i * (i + 1)) / 2) - i;
				for (int idx = 0; idx < i; idx++) {
					a_tuple_arr[the_relative_idx + idx] = { the_relative_idx + idx , i, idx };

				}
			}
		}

		int* calculate_ds_tuple_old(int the_n) {
			int* the_d_array;
			int* the_cuda_d_array;
			GCD_Tuple* the_cuda_tuple_array;

			int the_d_array_size = (the_n * (the_n + 1)) / 2;

			int the_d_array_byte_size = the_d_array_size * sizeof(int);

			int the_cuda_tuple_array_byte_size = the_d_array_size * sizeof(int);

			cudaMalloc((void**)&the_cuda_d_array, the_d_array_byte_size);
			cudaMalloc((void**)&the_cuda_tuple_array, the_cuda_tuple_array_byte_size);
			the_d_array = (int*)malloc(the_d_array_byte_size);

			int the_thread_num_a = the_n > BLOCK_SIZE ? BLOCK_SIZE : the_n;// Emulate Ceiling Division To Get Enough Blocks
			int the_block_num_a = the_n > BLOCK_SIZE ? (the_n + BLOCK_SIZE - 1) / BLOCK_SIZE : 1;
			calculate_d_tuples<<<the_block_num_a, the_thread_num_a>>>(the_cuda_tuple_array, the_n);

			int the_thread_num_b = the_d_array_size > BLOCK_SIZE ? BLOCK_SIZE : the_d_array_size;// Emulate Ceiling Division To Get Enough Blocks
			int the_block_num_b = the_d_array_size > BLOCK_SIZE ? (the_d_array_size + BLOCK_SIZE - 1) / BLOCK_SIZE : 1;
			calculate_gcds_via_tuples << <the_block_num_b, the_thread_num_b >> > (the_cuda_tuple_array, the_cuda_d_array, the_d_array_size);

			cudaMemcpy(the_d_array, the_cuda_d_array, the_d_array_byte_size, cudaMemcpyDeviceToHost);

			cudaFree(the_cuda_d_array);

			return the_d_array;
		}
*/

/*
	======[OLD IMPLEMENTATION]====== 

	1. Uses o(n^2) time complexity, because the while loops of gcd() are nested in for loops. 

	2. New Implementation is o(2n) since the for loops and while loops are now sequential

	======[OLD IMPLEMENTATION]======

		__device__ void calculate_gcds(int* a_start_address, int the_amount_to_calc) {

			for (int i = 0; i < the_amount_to_calc; i++) {

				int the_gcd = gcd(i, the_amount_to_calc);
				if (the_gcd == 1) a_start_address[i] = i;
				else a_start_address[i] = -1;

			}
		}



		__global__ void calculate_d(int* a_d_array, int a_n_value)
		{
			int i = blockDim.x * blockIdx.x + threadIdx.x + 1;

			if (i <= a_n_value) {
				int* the_start_address = &a_d_array[((i * (i + 1)) / 2) - i];

				calculate_gcds(the_start_address, i);
			}

		}


		int* calculate_ds(int the_n) {

			int* the_d_array;
			int* the_cuda_d_array;

			int the_d_array_size = (the_n * (the_n + 1)) / 2;

			int the_d_array_byte_size = the_d_array_size * sizeof(int);

			cudaMalloc((void**)&the_cuda_d_array, the_d_array_byte_size);
			the_d_array = (int*)malloc(the_d_array_byte_size);


			int the_thread_num = the_n > BLOCK_SIZE ? BLOCK_SIZE : the_n;

			// Emulate Ceiling Division To Get Enough Blocks
			int the_block_num = the_n > BLOCK_SIZE ? (the_n + BLOCK_SIZE - 1) / BLOCK_SIZE : 1;

			calculate_d << <the_block_num, the_thread_num >> > (the_cuda_d_array, the_n);

			cudaMemcpy(the_d_array, the_cuda_d_array, the_d_array_byte_size, cudaMemcpyDeviceToHost);

			cudaFree(the_cuda_d_array);

			return the_d_array;

		} 
*/