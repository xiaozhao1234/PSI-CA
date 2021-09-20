#include "PSI/include/Defines.h"
#include "PSI/include/utils.h"
#include "PSI/include/PsiSender.h"
#include "PSI/include/PsiReceiver.h"

#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Log.h>

#include <vector>

using namespace std;
using namespace PSI;

const block commonSeed = oc::toBlock(123456);

u64 senderSize;
u64 receiverSize;
u64 width;
u64 height;
u64 logHeight;
u64 hashLengthInBytes;
u64 bucket, bucket1, bucket2;
string ip;
int m;


void runSender() {
	IOService ios;
	Endpoint ep(ios, ip, EpMode::Server, "test-psi");
	Channel ch = ep.addChannel();

	vector<block> senderSet(senderSize);
	PRNG prng(oc::toBlock(123));
	for (auto i = 0; i < senderSize; ++i) {
		senderSet[i] = prng.get<block>();
	}
    senderSet[0] = osuCrypto::toBlock(1,1);
    for (auto i = 0; i < senderSize; ++i) {
        // std::cout << "senderSize["<<i<<"]="<<senderSet[i] << std::endl;
	}

//	PRNG prng2(oc::toBlock(456));
//	for (auto i = 256; i < senderSize; ++i) {
//		senderSet[i] = prng2.get<block>();
//	}

	PsiSender psiSender;
	psiSender.run(prng, ch, commonSeed, senderSize, receiverSize, height, logHeight, width, senderSet, hashLengthInBytes, 32, bucket1, bucket2);

	ch.close();
	ep.stop();
	ios.stop();
}

void runReceiver(int m) {
	IOService ios;
	Endpoint ep(ios, ip, EpMode::Client, "test-psi");
	Channel ch = ep.addChannel();

	vector<block> receiverSet(receiverSize);
	PRNG prng(oc::toBlock(123));
	// for (auto i = 0; i < 256; ++i) {
	// 	receiverSet[i] = prng.get<block>();
	// }

	PRNG prng2(oc::toBlock(456));
	for (auto i = 0; i < receiverSize; ++i) {
		receiverSet[i] = prng2.get<block>();
	}
    receiverSet[0] = osuCrypto::toBlock(1,1);
    for (auto i = 0; i < receiverSize; ++i) {
        // std::cout << "receiverSet["<<i<<"]="<<receiverSet[i] << std::endl;
	}

	PsiReceiver psiReceiver;
	psiReceiver.run(m,prng, ch, commonSeed, senderSize, receiverSize, height, logHeight, width, receiverSet, hashLengthInBytes, 32, bucket1, bucket2);

	ch.close();
	ep.stop();
	ios.stop();
}




int main(int argc, char** argv) {

	oc::CLP cmd;
	cmd.parse(argc, argv);

	cmd.setDefault("ss", 20);
	senderSize = 1 << cmd.get<u64>("ss");
//	senderSize = std::pow(2, senderSize);
    std::cout << "senderSize="<<senderSize << std::endl;


	cmd.setDefault("rs", 20);
	receiverSize = 1 << cmd.get<u64>("rs");
//	receiverSize = std::pow(2, receiverSize);
    std::cout << "receiverSize="<<receiverSize << std::endl;

	cmd.setDefault("w", 632);
	width = cmd.get<u64>("w");

	cmd.setDefault("h", 20);
	logHeight = cmd.get<u64>("h");
	height = 1 << cmd.get<u64>("h");

	cmd.setDefault("hash", 10);
	hashLengthInBytes = cmd.get<u64>("hash");

	cmd.setDefault("ip", "localhost");
	ip = cmd.get<string>("ip");

    cmd.setDefault("m", 2);
    m = cmd.get<int>("m");


	bucket1 = bucket2 = 1 << 8;


	bool noneSet = !cmd.isSet("r");
	if (noneSet) {
		std::cout
		<< "=================================\n"
		<< "||  Private Set Intersection   ||\n"
		<< "=================================\n"
		<< "\n"
		<< "This program reports the performance of the private set intersection protocol.\n"
		<< "\n"
		<< "Experimenet flag:\n"
		<< " -r 0    to run a sender.\n"
		<< " -r 1    to run a receiver.\n"
		<< "\n"
		<< "Parameters:\n"
		<< " -ss     log(#elements) on sender side.\n"
		<< " -rs     log(#elements) on receiver side.\n"
		<< " -w      width of the matrix.\n"
		<< " -h      log(height) of the matrix.\n"
		<< " -hash   hash output length in bytes.\n"
		<< " -ip     ip address (and port).\n"
		;
	} else {
		if (cmd.get<u64>("r") == 0) {
			runSender();
		} else if (cmd.get<u64>("r") == 1) {
			runReceiver(m);
		}
	}



	return 0;
}
