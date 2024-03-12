import { authenticate_post } from './pkg';


async function main() {
    //init();
    await authenticate_post(
        "at://did:web:genco.me/app.bsky.feed.post/3kmncrcuaus2o",
        "bafyreiau7hjyomncwrab5nvbsxah2bza4dsip6cjkek5x4wyer4i3kfkkm",
        {
            "text":"and commits from prs 500",
            "$type":"app.bsky.feed.post",
            "embed":{
                "$type":"app.bsky.embed.images",
                "images":[{
                    "alt":"",
                    "image":{
                        "$type":"blob",
                        "ref":{
                            "$link":"bafkreibje2n6qeeduvypr4hui7jdg4w6eabdjbhraespepxcaa5icsgflu"
                        },
                        "mimeType":"image/jpeg",
                        "size":325395
                    },
                    "aspectRatio":{
                        "width":2000,
                        "height":1214
                    }
                }]
            },
            "langs":["en"],
            "reply":{
                "root":{
                    "cid":"bafyreifsv6rjzhjoni4bn775v7l7m5kia5ukzg6qphkalf3c526ifospcy",
                    "uri":"at://did:web:genco.me/app.bsky.feed.post/3kmncq7o3rc2o"
                },
                "parent":{
                    "cid":"bafyreifsv6rjzhjoni4bn775v7l7m5kia5ukzg6qphkalf3c526ifospcy",
                    "uri":"at://did:web:genco.me/app.bsky.feed.post/3kmncq7o3rc2o"
                }
            },
            "createdAt":"2024-03-01T14:27:55.445Z"
        },
    );
}

main()