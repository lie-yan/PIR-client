function isPossibleCRT(mods) {
	for (x in mods) {
		for (y in mods) {
			if (x < y) {
				if (mods[x].gcd(mods[y]).equals(BigInteger.ONE))
					return false;
			}
		}
	}
	return true;
}

function ChineseRemainder(rems, mods) {
	if (isPossibleCRT(mods)) {
		return new BigInteger("-1", 10);
	} else {
		var prod = BigInteger.ONE;
		for (i in mods) {
			prod = prod.multiply(mods[i]);
		}
		var c_s = new Array();
		for (i in rems) {
			var Mi = prod.divide(mods[i]);
			var c = Mi.multiply(Mi.modInverse(mods[i]));
			c_s.push(c);
		}
		var sum = BigInteger.ZERO;
		for (i in rems) {
			sum = sum.add(rems[i].multiply(c_s[i]));
		}
		return sum.mod(prod);
	}
}
