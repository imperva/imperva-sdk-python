FAQ
***

**Q: Is imperva-sdk supported by Imperva?**

No. `imperva-sdk` is an open source project completely external to SecureSphere. It is not supported by Imperva in any way.

**Q: There is an MX SecureSphere API that isn't available in imperva-sdk, what to do?**

You can contribute to the `imperva-sdk` project and develop it yourself or open an issue in the GitHub repo.

**Q: Which SecureSphere versions does imperva-sdk work with?**

`imperva-sdk` should work with all versions of SecureSphere MX.
There might be certain APIs that are not available in older versions, in which case `imperva-sdk` should throw an exception when trying to use them.
If you find API version discrepancies that cause problems with `imperva-sdk`, please open a GitHub issue.

**Q: How does imperva-sdk handle exceptions?**

`imperva-sdk` has a proprietary exception Class (`MxException`) that works just like any other Python exception -

  >>> import imperva-sdk
  >>> mx = imperva-sdk.MxConnection("10.100.46.138")
  >>> site = mx.create_site("giora")
  >>> try:
  ...   site = mx.create_site("giora")
  ... except imperva-sdk.MxException as e:
  ...   print e
  ...
  Site already exists

**Q: I found a bug in imperva-sdk, what to do?**

Open a GitHub issue.
