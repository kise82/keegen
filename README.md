# `keegen`
## What is it?
My overly silly password generation utility.

## How it works
By owning a **private** 128 bytes file (`Keyfile`) and inputting a string (`seed`), one gets back a reasonable password that passes most password strength checks.

## Security
> [!CAUTION]
> I have ABSOLUTELY **NO** training, formal or informal, on cryptography or cryptanalysis.
> *I* **personally** **"**trust**"** this tool based on a few amateurish premises:
> - The randomness of the first 32 bytes (256 bits) of the Keyfile.
> - The resilience of the SHA-256 algorithm.
> - There are `2^66 * 12` (`885_443_715_538_058_477_568`) combinations for generated passwords; it'd average 14 years to brute force at 1 trillion combinations/second.
>
> Again, **no cryptanalysis countermeasure is guaranteed**.

> [!NOTE]
> Seeds are not needed to be secret: all security relies on the obscurity of the Keyfile!

## Extra: how to get a Keyfile?
 - On Unix: `dd if=/dev/urandom of=keyfile bs=128 count=1`
