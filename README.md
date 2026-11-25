# `keegen`

My overly silly, not very minimal password generator.

# Security

> [!CAUTION]
> I have ABSOLUTELY **NO** training, formal or informal, on cryptography or cryptanalysis.
> *I* **personally** **"**trust**"** this tool based on a single amateurish premise:
> - Passwords are 66 bits (+ more 6 for the single `+`), with a search space of `885,443,715,538,058,477,568` combinations.
>
> Again, **no cryptanalysis countermeasure is guaranteed**.

> [!NOTE]
> Password seeds are not meant to be secret: all security relies on the obscurity of the keyfile!

# Extra: how to get a keyfile?
 - On Unix: `dd if=/dev/urandom of=keyfile bs=128 count=1`
