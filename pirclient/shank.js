// object navigator created for running under Rhino engine
var navigator = new Object();
navigator.appName = "rhino";

// load libs
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/jsbn.js");
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/jsbn2.js");
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/prng4.js");
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/rng.js");

var rng = new SecureRandom();
var BigIntegerTWO   = new BigInteger("2", 10);
var BigIntegerTHREE = new BigInteger("3", 10);


function sqrt(x) {
	var TWO = new BigInteger("2", 10);
	var square = new BigInteger("1", 10);
	var delta  = new BigInteger("3", 10);
	
	while (square.compareTo(x) <= 0) {
		square = square.add(delta);
		delta = delta.add(TWO);
	}
	return delta.divide(TWO).subtract(BigInteger.ONE);
}

function ceilSqrt(x) {
	var root = sqrt(x);
	if (root.square().equals(x)) {
		return root;
	} else {
		return root.add(BigInteger.ONE);
	}
}

function pairCmp(a, b) {
	return a[1].compareTo(b[1]);
}

function bSearch(x, list) {
	var left = 0; 
	var right = list.length - 1;
	while (left <= right) {
		var mid = Math.floor((left+right)/2);
		print("mid="+mid);
		if (list[mid][1].equals(x)) {
			return list[mid][0];
		} else if (list[mid][1].compareTo(x) < 0){
			left = mid+1;
		} else {
			right = mid-1;
		}
	}
	return null;
}
// http://en.wikipedia.org/wiki/Baby-step_giant-step
function shank(alpha, beta, order, modulus) {
	var m = ceilSqrt(order);

	var list = new Array();
	for (var i = BigInteger.ZERO; i.compareTo(m) < 0; i = i.add(BigInteger.ONE)) {
		list.push([i, alpha.modPow(i, modulus)]);
	}
	list.sort(pairCmp);
	
	var inv_malpha = alpha.modPow(m, modulus).modInverse(modulus);
	var gamma = beta;
	
	for (var i = 0; i < m.intValue(); i++) {
		var j = bSearch(gamma, list);
		if (j != null) {
			var index = new BigInteger(i.toString(), 10);
			return index.multiply(m).add(j);
		} else {
			gamma = gamma.multiply(inv_malpha).mod(modulus);
		}
	}
}

