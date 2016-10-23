# emv-kernel

Proof of concept EMV kernel written in Go.

Should be compatible with EMV 4.3 and any card brand which implements the standard correctly (MasterCard, Visa, Amex, etc).

## EMV

EMV stands for Europay, MasterCard and Visa. You can read more about it [here](https://en.wikipedia.org/wiki/EMV#Versions).

This technology is used to authenticate genuine transactions in modern credit and debit cards.

## Whats an EMV Kernel?

An EMV Kernel is a piece of software capable of talking with an EMV ICC (the card chip) and processing a transaction correctly.

This includes implementing the EMV protocol, verifying chip authenticity, performing risk management and asking for the Application Cryptogram (AC), which is a cryptographic proof of the transaction used in the authorization process.

## Can I use it?

### No
Do not expect to use this in production, I can't guarantee that this will pass in any certification process.

Without certification (even with TBH), no acquirer will permit a transaction to be processed in its network. Also, typical EMV kernels are implemented by Point of Sale manufacturers and always run on secure hardware (as per the EMV Book and PCI PTS).

### Yes
This should work for Offline-Pin transactions which don't need to send the PIN enciphered with the acquirer key.

## How to use it

Just plug any PC/SC smart card reader with any compatible card inside.

## References

* http://www.openscdp.org/scripts/tutorial/emv/index.html
* https://www.emvco.com/specifications.aspx?id=223
* https://en.wikipedia.org/wiki/EMV
* The internet

## License

MIT.

