MODULE_APP =pcap2wav
CFLAGS = -D__LINUX__ -c -Wall -g -static
CXXFLAGS = $(CFLAGS) -std=gnu++0x

SRC = ./*.cpp
MODULE_APP:
	gcc $(CXXFLAGS) $(SRC) 

	#ar -rc adaptativeCodebookSearch.a adaptativeCodebookSearch.o

	#ar -rc codebooks.a codebooks.o

	#ar -rc computeAdaptativeCodebookGain.a computeAdaptativeCodebookGain.o

	#ar -rc computeLP.a computeLP.o

	#ar -rc computeWeightedSpeech.a computeWeightedSpeech.o

	#ar -rc decodeAdaptativeCodeVector.a decodeAdaptativeCodeVector.o

	#ar -rc decodeFixedCodeVector.a decodeFixedCodeVector.o

	#ar -rc decodeGains.a decodeGains.o

	#ar -rc decodeLSP.a decodeLSP.o

	#ar -rc decoder.a decoder.o

	#ar -rc encoder.a encoder.o

	#ar -rc findOpenLoopPitchDelay.a findOpenLoopPitchDelay.o

	#ar -rc fixedCodebookSearch.a fixedCodebookSearch.o

	#ar -rc gainQuantization.a gainQuantization.o

	#ar -rc interpolateqLSP.a interpolateqLSP.o

	#ar -rc LP2LSPConversion.a LP2LSPConversion.o

	#ar -rc LPSynthesisFilter.a LPSynthesisFilter.o

	#ar -rc LSPQuantization.a LSPQuantization.o

	#ar -rc pcm2wav.a pcm2wav.o

	#ar -rc postFilter.a postFilter.o

	#ar -rc postProcessing.a postProcessing.o

	#ar -rc preProcessing.a preProcessing.o

	#ar -rc qLSP2LP.a qLSP2LP.o
	#ar -rc utils.a utils.o

	g++ -o pcap2wav ./*.o
	
clean:
	rm -rdf ./*.a
	rm -rdf ./*.o
