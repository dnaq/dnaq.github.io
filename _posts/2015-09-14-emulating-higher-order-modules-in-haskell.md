---
layout: post
title: "Emulating higher order modules in Haskell"
description: ""
category: 
tags: [haskell, ffi, sodium, NaCl]
comments: false
---
{% include JB/setup %}

## Background

I'm currently writing bindings to the [sodium](https://doc.libsodium.org)
library for Haskell, which in turn is mainly a portable version of Dan
Bernsteins [NaCl](http://nacl.cr.yp.to) library. I'm also the author of the
[sodiumoxide](https://github.com/dnaq/sodiumoxide) bindings library for Rust.

## The Problem

NaCl defines a couple of different cryptographic primitives and those primitives
can have different implementations. For example `crypto_stream` is an API for
stream ciphers. NaCl exposes the implementations `aes128ctr`, `salsa20`,
`salsa208`, `salsa2012` and `xsalsa20`. That is, the API is the same, but the
actual implementation can be chosen by the user by using a suffix, e.g.
`crypto_stream_xsalsa20_stream_xor` is the encryption function when using
the `xsalsa20` primitive.

If we want to implement bindings for these API's in a naive way a lot of code will have to be duplicated. We will end up with something like:

```haskell
module Crypto.Sodium.Stream.Xsalsa20 where

-- skipped a lot of imports

foreign import ccall unsafe "crypto_stream_xsalsa20_keybytes"
    c_crypto_stream_xsalsa20_keybytes :: Int

-- skipped a lot of foreign imports

foreign import ccall unsafe "crypto_stream_xsalsa20_xor"
    c_crypto_stream_xsalsa20_xor :: Ptr Word8 -> Ptr CChar -> CULLong -> Ptr CChar -> Ptr CChar -> IO CInt

newtype Key = Key { unKey :: ByteString }
newtype None = Nonce { unNonce :: ByteString }

keyBytes :: Int
keyBytes = fromIntegral c_crypto_stream_xsalsa20_keybytes

randomKey :: IO Key
randomKey = Key <$> randomBytes keyBytes

streamXor :: Key -> Nonce -> ByteString -> ByteString
streamXor (Key k) (Nonce n) m =
    B.unsafeCreate mLen $ \pc ->
    B.unsafeUseAsCString m $ \pm ->
    B.unsafeUseAsCString n $ \pn ->
    B.unsafeUseAsCString k $ \pk ->
    void $ c_stream_xsalsa20_xor pc pm (fromIntegral mLen) pn pk

-- a lot more functions defined here
```

And then for AES-128-CTR we will need to define:

```haskell

module Crypto.Sodium.Stream.Aes128Ctr where

-- skipped a lot of imports

foreign import ccall unsafe "crypto_stream_aes128ctr_xor"
    c_crypto_stream_aes128ctr_xor :: Ptr Word8 -> Ptr CChar -> CULLong -> Ptr CChar -> Ptr CChar -> IO CInt

newtype Key = Key { unKey :: ByteString }
newtype None = Nonce { unNonce :: ByteString }

streamXor :: Key -> Nonce -> ByteString -> ByteString
streamXor (Key k) (Nonce n) m =
    B.unsafeCreate mLen $ \pc ->
    B.unsafeUseAsCString m $ \pm ->
    B.unsafeUseAsCString n $ \pn ->
    B.unsafeUseAsCString k $ \pk ->
    void $ c_stream_aes128ctr_xor pc pm (fromIntegral mLen) pn pk
    where mLen = B.length m

-- a lot more functions defined here
```

We don't really want to bother to write all of these instances manually. It's a lot of work, and the more code we're forced to write, the higher the risk that we introduce bugs somewhere.

In my rust library sodiumoxide I solved this by using macros. I defined a macro
`stream_module` and then instantiated that macro for each cryptographic
primitive.

## Solution 1 (Type Classes)

The first thing that I thought of was to create some kind of type class for a stream cipher.
Something like:

```haskell

newtype Key s = Key { unKey :: ByteString }
newtype Nonce s = Nonce { unNonce :: ByteString }

class StreamCipher s where
    c_crypto_stream_keybytes :: Tagged s Int
    c_crypto_stream_noncebytes :: Tagged s Int
    c_crypto_stream_xor :: Tagged s (Ptr Word8 -> Ptr CChar -> CULLong -> Ptr CChar -> Ptr CChar -> IO CInt)

streamXor :: StreamCipher s => Key s -> Nonce s -> ByteString -> ByteString
streamXor (Key k) (Nonce n) = 

streamXor :: forall s. StreamCipher s => Key s -> Nonce s -> ByteString -> ByteString
streamXor (Key k) (Nonce n) =
    B.unsafeCreate mLen $ \pc ->
    B.unsafeUseAsCString m $ \pm ->
    B.unsafeUseAsCString n $ \pn ->
    B.unsafeUseAsCString k $ \pk ->
    void $ c_stream_xor' pc pm (fromIntegral mLen) pn pk
    where
        mLen = B.length m
        c_stream_xor' = untag (c_stream_xor :: Tagged s (Ptr Word8 -> Ptr CChar -> CULLong -> Ptr CChar -> Ptr CChar -> IO CInt))
```

And we can use it like

```haskell

foreign import ccall unsafe "crypto_stream_xsalsa20_keybytes"
    c_crypto_stream_xsalsa20_keybytes :: CInt

foreign import ccall unsafe "crypto_stream_xsalsa20_noncebytes"
    c_crypto_stream_xsalsa20_noncebytes :: CInt

foreign import ccall unsafe "crypto_stream_xsalsa20_xor"
    c_crypto_stream_xsalsa20_xor :: Ptr Word8 -> Ptr CChar -> CULLong -> Ptr CChar -> Ptr CChar -> IO CInt

data Xsalsa20
instance StreamCipher Xsalsa20 where
    c_crypto_stream_keybytes = Tagged c_crypto_stream_xsalsa20_keybytes
    c_crypto_stream_noncebytes :: Tagged c_crypto_stream_xsalsa20_noncebytes
    c_crypto_stream_xor = Tagged c_crypto_stream_xsalsa20_xor
```

This will work, but will introduce a lawless type-class. That might be the best
solution, but I'm a bit wary of lawless type-classes. Also we're not really
looking to write functions polymorphic in stream ciphers, we just want to reduce
code duplication.

We will also need to create a dispatching type (e.g. `Xsalsa20`) for all of our different
cryptographic primitives manually. Some cryptographic libraries dispatch on the `Key` type,
but that would force us to define the `Key` types manually, and would also cause issues since
we have a `Nonce` type as well. That would require us to do someting like:

```haskell
class StreamCipher k n | k -> n, n -> k where
    ...
```

(or use `TypeFamilies` to achieve the same thing)

### PROS
- Might be the most idiomatic solution

### CONS
- Lawless type class
- Need to define a dispatching type (or dispatch on the `Key` type which will
  lead to more boilerplate)
- A user wanting to (for example) generate keys with a `randomKey :: StreamCipher s => IO (Key s)` function might need to annotate the type manually instead of just importing the correct module.

## Solution 2 (Macro Instantiation)
The closest thing to using rust macros is to use some kind of macros in Haskell as well.

### CPP
The easiest way to do that is probably to use a CPP macro to generate our code for us
with textual substitutions.

```haskell
#define STREAM_MODULE(name, primitive)
```

However I ran into some issues with parameter substitutions in the foreign import strings, probably nothing that can't be solved, but I didn't really want to use CPP (maybe for all the wrong reasons).

### Template Haskell
Instead of CPP we can use Template Haskell to autogenerate the module bodies for
us. I won't go into detail on the code, but we can quite easily create a
template haskell function that imports all of the foreign functions and creates
all function definitions for us. This comes with the drawback of making
cross-compilation a bit hard. It will also increase binary size, since we will
duplicate all definitions for all of our cryptographic primitives.

So if we define a template haskell function `mkStream :: String -> Q [Dec]` that
takes a primitive name and does all the foreign imports, datatype definitions
and function definitions for us we don't have to do the work manually.

I actually implemented this solution first, but tried to think of other solutions that didn't need Template Haskell.

### PROS
- No need to import foreign functions manually
- No need for a dispatching datatype

### CONS
- Bad cross-compilation story
- Code size growth
- A lot of people seem to dislike Template Haskell

## Solution 3 (plain old datatypes)
If we instead write something like this:

```haskell

{-# LANGUAGE RecordWildCards #-}
module Stream.Internal where

type XorFn = Ptr Word8 -> Ptr CChar -> CULLong -> Ptr CChar -> Ptr CChar -> IO CInt

newtype Key s = Key { _unKey :: ByteString }
newtype Nonce s = Nonce { _unNonce :: ByteString }

data StreamCipher s = StreamCipher
    { keyBytes :: Int
    , nonceBytes :: Int
    , ...
    , streamXor :: Key s -> Nonce s -> ByteString -> ByteString
    }

mkStream :: CInt -> CInt -> XorFn -> StreamCipher s
mkStream c_keyBytes c_nonceBytes c_streamXor =
    StreamCipher {..}
    where
        keyBytes = fromIntegral c_keyBytes
        nonceBytes = fromIntegral c_nonceBytes
        streamXor (Key k) (Nonce n) m =
            B.unsafeCreate mLen $ \pc ->
            B.unsafeUseAsCString m $ \pm ->
            B.unsafeUseAsCString n $ \pn ->
            B.unsafeUseAsCString k $ \pk ->
            void $ c_streamXor pc pm (fromIntegral mLen) pn pk
        where mLen = B.length m
```

Then we can use it like

```haskell

module Stream.Xsalsa20 where

foreign import ccall unsafe "crypto_stream_xsalsa20_keybytes"
    c_crypto_stream_xsalsa20_keybytes

foreign import ccall unsafe "crypto_stream_xsalsa20_noncebytes"
    c_crypto_stream_xsalsa20_noncebytes

foreign import ccall unsafe "crypto_stream_xsalsa20_xor"
    c_crypto_stream_xsalsa20_xor

data Xsalsa20

xsalsa20 :: StreamCipher Xsalsa20
xsalsa20 = mkStream c_crypto_stream_xsalsa20_keybytes c_crypto_stream_xsalsa20_noncebytes
                    c_crypto_stream_xsalsa20_xor 

StreamCipher {..} = xsalsa20
```

With this solution we still need to write all of our foreign imports manually,
and also add a bit of boilerplate like the phantom type that we use to
instantiate or functions. However using `RecordWildCards` we get all top-level
definitions for free without using type classes. I added `{-# OPTIONS_GHC -fno-warn-missing-signatures #-}` to the source files as well to be able to compile with `-Wall` without the compiler complaining about missing signature.

### PROS
- No code growth
- No need for template haskell
- No lawless type class

### CONS
- Still some boilerplate remaining

## Summary
This was an overview of different ways to emulate higher order modules in
Haskell. I have chosen the last approach for my library. I wrote this up to see
if anyone else finds it interesting and also to generate discussion on different
ways to solve this problem.

## Open Questions
- Is there a better way to solve this problem?
- Should I have gone with the type class approach instead?

Please join the [reddit](https://haskell.reddit.com) discussion for comments.
