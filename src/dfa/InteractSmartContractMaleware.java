package dfa;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.awt.List;
import java.io.File;
import java.math.BigInteger;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tuples.generated.Tuple3;
import test.malware.MalwareTest;

import rx.Subscription;

public class InteractSmartContractMaleware {
	public static void main (String[] args) throws Exception {
		Web3j web3j = Web3j.build(new HttpService());  // defaults to http://localhost:8545/ 
		@SuppressWarnings("unused")
		final String timeout = null;
		String contractAddress = "0x1b25fd1050c6908324245be0b1c47378fb71fcca";
		File file = new File("D:\\eth_test\\keystore\\UTC--2018-09-03T23-08-14.524286100Z--aed900d3ff41decff449b2978d66d2aeab42099e");

		String Pass = "password";
		BigInteger  gasLimit = new BigInteger("3000000");

		BigInteger  gasPrice = new BigInteger("0");
		
		Credentials credentials = WalletUtils.loadCredentials(Pass, file); //PROBLEM IS HERE
		
		MalwareTest malwareFunction = new MalwareTest();
		malwareFunction.stealData(Pass, "imei", gasLimit, gasPrice);
		

		Malware malware = Malware.load(contractAddress, web3j, credentials, gasPrice, gasLimit);
		
//		SET DATE AND TIME TO NOW
		final DateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

		Date date = new Date();
		@SuppressWarnings("unused")
		TransactionReceipt transactionReceipt = malware.setMalware("Maleware", "Type", sdf.format(date)).send();
		@SuppressWarnings("rawtypes")
		Tuple3 data = malware.getMalware().send();
		
		System.out.println("Print: Maleware: " + data.getValue1() + " Type: " + data.getValue2() + " Age: " + data.getValue3());
		
		System.out.println("TRANSACTION Address: " + transactionReceipt.getFrom());
		
	}
}
