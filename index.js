import { init, authenticate_post, authenticate_post_with_doc } from "./pkg";

async function main() {
  init();
  await authenticate_post_with_doc(
    "at://did:plc:ia76kvnndjutgedggx2ibrem/app.bsky.feed.post/3lbckva5qqksv",
    "bafyreieiof45ascpryjyodac4j5chhi5o4svygejbm4tp2hfouitxpi7ba",
    {
      text: "◌ i got the custom emojis but bsky.app doesnt support it",
      $type: "app.bsky.feed.post",
      langs: ["en"],
      reply: {
        root: {
          cid: "bafyreidwmohm4mqkxcqc2cixys5kvwwirt2qa6456r7iznoaao473lu4m4",
          uri: "at://did:plc:2lyulz5o63to3boaerwqafxj/app.bsky.feed.post/3lbcjidr3m22a",
        },
        parent: {
          cid: "bafyreihccrablzmlapabuhnfdx2unrqbc4dvmdz4yhi2gkpacwa2zji54i",
          uri: "at://did:plc:2lyulz5o63to3boaerwqafxj/app.bsky.feed.post/3lbcktfz3q22x",
        },
      },
      facets: [
        {
          index: { byteEnd: 3, byteStart: 0 },
          features: [
            {
              did: "did:plc:ia76kvnndjutgedggx2ibrem",
              name: "◌",
              $type: "blue.moji.richtext.facet",
              formats: {
                $type: "blue.moji.richtext.facet#formats_v0",
                png_128:
                  "bafkreif32i7xs4ltlattqepkodgsqt5o7j44bfwdigjdz3u7vrgim4xwwm",
                webp_128:
                  "bafkreichujvpqyapxnke5uj7mc7p6k5kqprtxbfssstoj6xjh36kcetjoe",
              },
            },
            {
              uri: "https://github.com/aendra-rininsland/bluemoji",
              $type: "app.bsky.richtext.facet#link",
            },
          ],
        },
      ],
      createdAt: "2024-11-19T13:43:03.905Z",
    },
    {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1",
        "https://w3id.org/security/suites/secp256k1-2019/v1",
      ],
      id: "did:plc:ia76kvnndjutgedggx2ibrem",
      alsoKnownAs: ["at://mary.my.id"],
      verificationMethod: [
        {
          id: "did:plc:ia76kvnndjutgedggx2ibrem#atproto",
          type: "Multikey",
          controller: "did:plc:ia76kvnndjutgedggx2ibrem",
          publicKeyMultibase:
            "zQ3shuqiNQXNGKBBbNvPhcaZy8DjP3BF3yhmSeAjFXQjgPJrG",
        },
      ],
      service: [
        {
          id: "#atproto_pds",
          type: "AtprotoPersonalDataServer",
          serviceEndpoint: "https://porcini.us-east.host.bsky.network",
        },
      ],
    },
  );
}

await main();
console.log("done!");
