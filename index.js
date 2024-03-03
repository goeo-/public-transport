import { authenticate_post } from './pkg';


async function main() {
    await authenticate_post(
        "at://did:plc:nna2tjuxqm6e5kaie5iul42e/app.bsky.feed.post/3kmntv5eutc2c",
        "bafyreidk5kuawhnzmyf3ma6vqhwpmzsbd6rbbzr3d5j7z2t5wqo33nvoya",
        {
            "text":"New blog! \"BGGP4: A 420 Byte Self-Replicating UEFI App For x64\"\n\nI cover UEFI, the UEFI x64 ABI, writing UEFI applications in x86_64 assembly, Tianocore EDK2 image loader internals, QEMU automation, and binary golf strategies for UEFI PEs.\n\nHappy Friday!\n\ngithub.com/netspooky/go...",
            "$type":"app.bsky.feed.post",
            "embed":{
                "$type":"app.bsky.embed.images",
                "images":[
                    {
                        "alt":"A screenshot of a terminal with a hex dump of a UEFI app, the size (420 bytes), and the app running in QEMU.",
                        "image":{
                            "ref":{
                                "$link":"bafkreibvfwoz6zfm7q4zrgxonmzzp7wlsmbih7wznjcsejw7mcjm5hq5oi"
                            },
                            "size":425919,
                            "$type":"blob",
                            "mimeType":"image/jpeg"
                        },
                        "aspectRatio":{"width":528,"height":520}
                    }
                ]
            },
            "langs":["en"],
            "facets":[
                {
                    "index":
                        {
                            "byteEnd":282,
                            "byteStart":256
                        },
                    "features":[
                        {
                            "uri":"https://github.com/netspooky/golfclub/tree/master/uefi/bggp4",
                            "$type":"app.bsky.richtext.facet#link"
                        }
                    ]
                }
            ],
            "createdAt":"2024-03-01T19:34:17.532Z"
        }
    );
}

main()