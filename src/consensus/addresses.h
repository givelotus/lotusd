#include <string>
#include <vector>

#include <consensus/params.h>

namespace RewardAddresses {
Consensus::CoinbaseAddresses AddressSets = {
    .genesis =
        {
            // Foundation
            "pzmv0yp3kuwcd2cdv9lpu8nsdmzwud9s0upp4rxwc9",
            // Bitcoin ABC
            "qzu2u8z8ala43ae0009gr8l8lsjjl8599cdwdr9mxq",
            // Tobias
            "qz6shp4gj0vqe83wuu43n9sjxa9hknqumq0xdtwprp",
            // Saipan Institute
            "qrd8dgcmvasdewg2535uzkt9mfhgqztwg504dhsfxc",
            // Stamp
            "qqfjt5kchfhgclvelandy9fsj97vwdpf6g7sfclqsh",
            // Nghia
            "qp4pwxy34w2yxqst6f64aauudev7l3vjv5xg6dhc7x",
            // Remark
            "qqv73kxsak4ka3plqjm9d0lh9tmc6cllv5m9np8ndy",
            // Bitcoin Not Bombs
            "qrryjt2wgnwdqpg7vz52m440q2e09ydj4gupmhu3g6",
            // Distro Bot
            "qz66atlvnu5hyygvf340j5y283q7r5788vkcu6qff3",
            // Distro Bot
            "qp7z3253hyl6lzhwpfjjpg9g8apdh39ytvlwfx57mm",
            // Evangelism
            "qzccavyvf9uwwdyqwsa3txqxr5708rss4qqg8p6an4",
            // Distro Bot
            "qp7s3y735fut4vn70tvjakyt6lww4lvr55ljvaxpyn",
            // Distro Bot
            "qp9cd8u62hzhqq7lz79aeqq3ssgfmyz03vc5c4g0ct",
        },
    .exodus =
        {
            // Aleph 0
            "lotus_16PSJNf1EDEfGvaYzaXJCJZrXH4pgiTo7kyW61iGi",
            // Maintainance
            "lotus_16PSJNZhPZSyLeQaiEdy3a3gZdwQ2yAPqUm7WHRzN",
            // Stamp
            "lotus_16PSJHhULzYgupzGnvDysUFLxYxBVwx92JjXSyjNL",
            // VN
            "lotus_16PSJLMtCuFnyMb3rz4zbbhAtJgppp8GiY5NpGGev",
            // Explorer
            "lotus_16PSJJQGXSV1uMG2JHERQpVL3pVH7nwqu2YSiX96t",
            // Distro
            "lotus_16PSJHEXKQEL5M28Rc8rvYntymdKtPmVXJDEtbFLi",
            // Evangelism
            "lotus_16PSJNnGguQxEhHHW569L3g3MfhCNsS1Q6AWrJ8AH",
            // Lotusia Citizen 1
            "lotus_16PSJP5wAt1F45LycobZssN8Jk3TaR6QL9AXcRRty",
            // Marketing
            "lotus_16PSJHej3n56z43NC4PgYAAubk8opBXt7JXXfHjwc",
            // Lotusia Citizen 2
            "lotus_16PSJJSRTKjXKkvMtV6NX8SVEbTBwpjCWxQP7bHdi",
            // Bots
            "lotus_16PSJHuUsbDo5qZUjygQgtJLMsZgcpSB6wD459F6J",
            // Bot
            "lotus_16PSJJXVKnYb8xtUhHyBDSdd8P2xx6suUM7TaWBNx",
            // Lotusia Citizen 3
            "lotus_16PSJKHmQ2Lm8BNtnvPi1jC4rxJpCo8VqvJecj5Hb",
        },
    .leviticus =
        {
            // Aleph 0
            "lotus_16PSJQTQMPHoT5AuGLm2UHcmbKLEFR43gHJChzTUy",
            // Maintainance
            "lotus_16PSJJdodJ4VMACYzBd1ey1MiPaaT5XSWVnoxQvci",
            // Stamp
            "lotus_16PSJHhULzYgupzGnvDysUFLxYxBVwx92JjXSyjNL",
            // VN
            "lotus_16PSJLMtCuFnyMb3rz4zbbhAtJgppp8GiY5NpGGev",
            // Explorer 2
            "lotus_16PSJMBaU1g7jvzCrXUCK5gxP6GHnSxEBYR3geqtX",
            // Sales
            "lotus_16PSJQ3Wby3uP6XkPtKTULTFzMXU9JJXfr1UrzTZJ",
            // Radical Evangelism
            "lotus_16PSJJjTw855ea3eJqEPTsuG6PkmLJw5eW4WVUjS7",
            // Buddhism
            "lotus_16PSJQEzUwA2bpbkzvAiDtAviX1Ep5x9x5UhdcBV6",
            // VN 2
            "lotus_16PSJNgypXoCzC2yQqz7wTGFCSL25qv4XZhxvQ28A",
            // Ministry Of Truth
            "lotus_16PSJKEP97unf4XFVR6zzS3j2s3qJp8omSJkyyDWH",
            // Podcasters
            "lotus_16PSJMwWGF6jNTbF8WgMuM49DZNmsWgY3b5e4itvd",
            // Bots
            "lotus_16PSJHuUsbDo5qZUjygQgtJLMsZgcpSB6wD459F6J",
            // Lotus Citizen 4
            "lotus_16PSJNEqzEoLhBigDN8Hf93FzERrPQKJXaYdzRCNT",
        },
    .numbers =
        {
            "lotus_16PSJKzohkeX3G5BKpbeESKZZCHWrQymNRwjsu42Y",
            "lotus_16PSJHtDqN7ibmc4NSziqbrmAXoSLE46F9LceMUDx",
            "lotus_16PSJHhULzYgupzGnvDysUFLxYxBVwx92JjXSyjNL",
            "lotus_16PSJLTMsACkicNJVmAPBQgmEeagvkXKuF8gR2qE8",
            "lotus_16PSJPfz8J1KkScQUMZK8GabJgTGxr8c5WWidEQYS",
            "lotus_16PSJN2GzCj6PVwg4oTbiXftP7Jf3Ux2zB3X4A6Dw",
            "lotus_16PSJMtQgty32UmgzkomZYPavZaJb8kn3HUeD4jno",
            "lotus_16PSJLMtCuFnyMb3rz4zbbhAtJgppp8GiY5NpGGev",
            "lotus_16PSJP1z4qX4XeJprHPgw2GbY86GxMwT2DKmVmHqS",
            "lotus_16PSJNob8nN2U5e1WfpvpHbn28iJ8mr5ZbjsTNmzk",
            "lotus_16PSJM1j9nPx6xLbyJ4UMsT1XNMdZAsT6vayCiEhh",
            "lotus_16PSJL7B1pQm4pT3M4k6BeXNR8PXkvuv8BeosgUdA",
            "lotus_16PSJNfvYdAquq6X28omdnpMyixZX9JfF9MgmDX3H",
        },
    .deuteronomy =
        {
            "lotus_16PSJHaDBFwmD1HPVWv3zLo3dbXMZTnCgBRzqFusu",
            "lotus_16PSJMKqnLMJYonvMdn4mVqMb3bG5C76spwKuW4DL",
            "lotus_16PSJHedfWvFixJzv5pV7g3FY2Z62kT9NprSqfYxW",
            "lotus_16PSJJeYibqH7K189RbonEcoR7djvw54HWBebPQLY",
            "lotus_16PSJJPzQYbd5JCX8UpukirFGz9hmCWFjGAhByDip",
            "lotus_16PSJLr6AKaWTgioeJbjUWFAdq7yVDG17PQ1WoFn1",
            "lotus_16PSJLr6AKaWTgioeJbjUWFAdq7yVDG17PQ1WoFn1",
            "lotus_16PSJMStv9sve3DfhDpiwUCa7RtqkyNBoS8RjFZSt",
            "lotus_16PSJMStv9sve3DfhDpiwUCa7RtqkyNBoS8RjFZSt",
            "lotus_16PSJLMtCuFnyMb3rz4zbbhAtJgppp8GiY5NpGGev",
            "lotus_16PSJLMtCuFnyMb3rz4zbbhAtJgppp8GiY5NpGGev",
            "lotus_16PSJMzCWkYt58BCiBTkgBGJ9usFfNTRKq6anVLbG",
            "lotus_16PSJMzCWkYt58BCiBTkgBGJ9usFfNTRKq6anVLbG",
            "lotus_16PSJMzCWkYt58BCiBTkgBGJ9usFfNTRKq6anVLbG",
            "lotus_16PSJMzCdB851yS4m59RUG5CKfjhJxTSWBo8EK1os",
            "lotus_16PSJMzCdB851yS4m59RUG5CKfjhJxTSWBo8EK1os",
            "lotus_16PSJMzCdB851yS4m59RUG5CKfjhJxTSWBo8EK1os",
            "lotus_16PSJHA7AxHkiV4XACtMRSzKmw8F1pT3ZbsEnzJ4s",
            "lotus_16PSJHA7AxHkiV4XACtMRSzKmw8F1pT3ZbsEnzJ4s",
            "lotus_16PSJHA7AxHkiV4XACtMRSzKmw8F1pT3ZbsEnzJ4s",
            "lotus_16PSJHA7AxHkiV4XACtMRSzKmw8F1pT3ZbsEnzJ4s",
            "lotus_16PSJHA7AxHkiV4XACtMRSzKmw8F1pT3ZbsEnzJ4s",
        },
    .joshua =
        {
            "lotus_16PSJJYp3YkVyctW8LRbp6UhbsrQMJghL3jjze3b7",
        },
    .judges =
        {
            "lotus_16PSJMaps9sQg7aBQgyY1RdHb2fZYdmWhQPbgus75"
        }
};
} // namespace RewardAddresses
