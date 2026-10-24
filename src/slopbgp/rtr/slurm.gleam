import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import slopbgp/dn42/roa.{validate_route}
import slopbgp/ip.{is_prefix_contained, parse_prefix, prefix_to_string}
import slopbgp/types.{
  type IpPrefix, type RoaEntry, type RoaStatus, RoaInvalid, RoaValid,
}

// RFC 8416: Simplified Local Internet Number Resource Management with the RPKI (SLURM)

pub type SlurmPrefixFilter {
  SlurmPrefixFilter(
    prefix: Option(IpPrefix),
    asn: Option(Int),
    comment: Option(String),
  )
}

pub type SlurmBgpsecFilter {
  SlurmBgpsecFilter(
    asn: Option(Int),
    ski: Option(String),
    comment: Option(String),
  )
}

pub type SlurmPrefixAssertion {
  SlurmPrefixAssertion(
    prefix: IpPrefix,
    max_prefix_length: Option(Int),
    asn: Int,
    comment: Option(String),
  )
}

pub type SlurmBgpsecAssertion {
  SlurmBgpsecAssertion(
    asn: Int,
    ski: String,
    router_public_key: String,
    comment: Option(String),
  )
}

pub type SlurmFile {
  SlurmFile(
    slurm_version: Int,
    prefix_filters: List(SlurmPrefixFilter),
    bgpsec_filters: List(SlurmBgpsecFilter),
    prefix_assertions: List(SlurmPrefixAssertion),
    bgpsec_assertions: List(SlurmBgpsecAssertion),
  )
}

pub fn new_slurm() -> SlurmFile {
  SlurmFile(
    slurm_version: 1,
    prefix_filters: [],
    bgpsec_filters: [],
    prefix_assertions: [],
    bgpsec_assertions: [],
  )
}

// --- Filtering ROA tables per RFC 8416 Section 3.2 ---

pub fn filter_roa_entry(
  entry: RoaEntry,
  filters: List(SlurmPrefixFilter),
) -> Bool {
  list.any(filters, fn(f) {
    case f.prefix, f.asn {
      Some(fp), Some(fa) ->
        is_prefix_contained(entry.prefix, fp) && entry.asn == fa
      Some(fp), None -> is_prefix_contained(entry.prefix, fp)
      None, Some(fa) -> entry.asn == fa
      None, None -> False
    }
  })
}

pub fn filter_roa_table(
  roas: List(RoaEntry),
  filters: List(SlurmPrefixFilter),
) -> List(RoaEntry) {
  list.filter(roas, fn(entry) { !filter_roa_entry(entry, filters) })
}

// --- Evaluating Routes with SLURM overrides ---

pub fn evaluate_slurm_route(
  prefix: IpPrefix,
  origin_asn: Int,
  roas: List(RoaEntry),
  slurm: SlurmFile,
) -> RoaStatus {
  // 1. Check local prefix assertions first (RFC 8416 Section 3.3)
  let covering_assertions =
    list.filter(slurm.prefix_assertions, fn(a) {
      is_prefix_contained(prefix, a.prefix)
    })

  case covering_assertions {
    [assertion, ..] -> {
      let max_len =
        option.unwrap(assertion.max_prefix_length, assertion.prefix.length)
      case prefix.length <= max_len && origin_asn == assertion.asn {
        True -> RoaValid
        False -> RoaInvalid
      }
    }
    [] -> {
      // 2. Filter global/RTR ROA table with prefix filters
      let active_roas = filter_roa_table(roas, slurm.prefix_filters)
      // 3. Perform RFC 6811 validation
      validate_route(prefix, origin_asn, active_roas)
    }
  }
}

// --- JSON Serialization per RFC 8416 Section 3.4 ---

pub fn encode_slurm(slurm: SlurmFile) -> String {
  let pfx_filters_json =
    list.map(slurm.prefix_filters, fn(f) {
      let fields = []
      let fields = case f.prefix {
        Some(p) -> [#("prefix", json.string(prefix_to_string(p))), ..fields]
        None -> fields
      }
      let fields = case f.asn {
        Some(a) -> [#("asn", json.int(a)), ..fields]
        None -> fields
      }
      let fields = case f.comment {
        Some(c) -> [#("comment", json.string(c)), ..fields]
        None -> fields
      }
      json.object(fields)
    })

  let bgpsec_filters_json =
    list.map(slurm.bgpsec_filters, fn(f) {
      let fields = []
      let fields = case f.asn {
        Some(a) -> [#("asn", json.int(a)), ..fields]
        None -> fields
      }
      let fields = case f.ski {
        Some(s) -> [#("ski", json.string(s)), ..fields]
        None -> fields
      }
      let fields = case f.comment {
        Some(c) -> [#("comment", json.string(c)), ..fields]
        None -> fields
      }
      json.object(fields)
    })

  let pfx_assertions_json =
    list.map(slurm.prefix_assertions, fn(a) {
      let fields = [
        #("prefix", json.string(prefix_to_string(a.prefix))),
        #("asn", json.int(a.asn)),
      ]
      let fields = case a.max_prefix_length {
        Some(m) -> [#("maxPrefixLength", json.int(m)), ..fields]
        None -> fields
      }
      let fields = case a.comment {
        Some(c) -> [#("comment", json.string(c)), ..fields]
        None -> fields
      }
      json.object(fields)
    })

  let bgpsec_assertions_json =
    list.map(slurm.bgpsec_assertions, fn(a) {
      let fields = [
        #("asn", json.int(a.asn)),
        #("ski", json.string(a.ski)),
        #("routerPublicKey", json.string(a.router_public_key)),
      ]
      let fields = case a.comment {
        Some(c) -> [#("comment", json.string(c)), ..fields]
        None -> fields
      }
      json.object(fields)
    })

  json.object([
    #("slurmVersion", json.int(slurm.slurm_version)),
    #(
      "validationOutputFilters",
      json.object([
        #("prefixFilters", json.preprocessed_array(pfx_filters_json)),
        #("bgpsecFilters", json.preprocessed_array(bgpsec_filters_json)),
      ]),
    ),
    #(
      "locallyAddedAssertions",
      json.object([
        #("prefixAssertions", json.preprocessed_array(pfx_assertions_json)),
        #("bgpsecAssertions", json.preprocessed_array(bgpsec_assertions_json)),
      ]),
    ),
  ])
  |> json.to_string
}

// --- JSON Deserialization ---

type RawPrefixFilter {
  RawPrefixFilter(
    prefix: Option(String),
    asn: Option(Int),
    comment: Option(String),
  )
}

type RawBgpsecFilter {
  RawBgpsecFilter(
    asn: Option(Int),
    ski: Option(String),
    comment: Option(String),
  )
}

type RawPrefixAssertion {
  RawPrefixAssertion(
    prefix: String,
    max_prefix_length: Option(Int),
    asn: Int,
    comment: Option(String),
  )
}

type RawBgpsecAssertion {
  RawBgpsecAssertion(
    asn: Int,
    ski: String,
    router_public_key: String,
    comment: Option(String),
  )
}

type RawSlurm {
  RawSlurm(
    slurm_version: Int,
    prefix_filters: List(RawPrefixFilter),
    bgpsec_filters: List(RawBgpsecFilter),
    prefix_assertions: List(RawPrefixAssertion),
    bgpsec_assertions: List(RawBgpsecAssertion),
  )
}

pub fn decode_slurm(json_str: String) -> Result(SlurmFile, String) {
  let pfx_filter_decoder = {
    use prefix <- decode.optional_field(
      "prefix",
      None,
      decode.optional(decode.string),
    )
    use asn <- decode.optional_field("asn", None, decode.optional(decode.int))
    use comment <- decode.optional_field(
      "comment",
      None,
      decode.optional(decode.string),
    )
    decode.success(RawPrefixFilter(prefix, asn, comment))
  }

  let bgpsec_filter_decoder = {
    use asn <- decode.optional_field("asn", None, decode.optional(decode.int))
    use ski <- decode.optional_field(
      "ski",
      None,
      decode.optional(decode.string),
    )
    use comment <- decode.optional_field(
      "comment",
      None,
      decode.optional(decode.string),
    )
    decode.success(RawBgpsecFilter(asn, ski, comment))
  }

  let pfx_assertion_decoder = {
    use prefix <- decode.field("prefix", decode.string)
    use max_pfx_len <- decode.optional_field(
      "maxPrefixLength",
      None,
      decode.optional(decode.int),
    )
    use asn <- decode.field("asn", decode.int)
    use comment <- decode.optional_field(
      "comment",
      None,
      decode.optional(decode.string),
    )
    decode.success(RawPrefixAssertion(prefix, max_pfx_len, asn, comment))
  }

  let bgpsec_assertion_decoder = {
    use asn <- decode.field("asn", decode.int)
    use ski <- decode.field("ski", decode.string)
    use router_pub_key <- decode.field("routerPublicKey", decode.string)
    use comment <- decode.optional_field(
      "comment",
      None,
      decode.optional(decode.string),
    )
    decode.success(RawBgpsecAssertion(asn, ski, router_pub_key, comment))
  }

  let slurm_decoder = {
    use version <- decode.field("slurmVersion", decode.int)
    use filters <- decode.field("validationOutputFilters", {
      use pf <- decode.optional_field(
        "prefixFilters",
        [],
        decode.list(pfx_filter_decoder),
      )
      use bf <- decode.optional_field(
        "bgpsecFilters",
        [],
        decode.list(bgpsec_filter_decoder),
      )
      decode.success(#(pf, bf))
    })
    use assertions <- decode.field("locallyAddedAssertions", {
      use pa <- decode.optional_field(
        "prefixAssertions",
        [],
        decode.list(pfx_assertion_decoder),
      )
      use ba <- decode.optional_field(
        "bgpsecAssertions",
        [],
        decode.list(bgpsec_assertion_decoder),
      )
      decode.success(#(pa, ba))
    })

    let #(pf, bf) = filters
    let #(pa, ba) = assertions
    decode.success(RawSlurm(version, pf, bf, pa, ba))
  }

  case json.parse(json_str, slurm_decoder) {
    Ok(raw) -> {
      let pfx_filters_res =
        result.all(
          list.map(raw.prefix_filters, fn(rf) {
            case rf.prefix {
              Some(p_str) -> {
                use p <- result.try(parse_prefix(p_str))
                Ok(SlurmPrefixFilter(Some(p), rf.asn, rf.comment))
              }
              None -> Ok(SlurmPrefixFilter(None, rf.asn, rf.comment))
            }
          }),
        )
      use pfx_filters <- result.try(pfx_filters_res)

      let bgpsec_filters =
        list.map(raw.bgpsec_filters, fn(rf) {
          SlurmBgpsecFilter(rf.asn, rf.ski, rf.comment)
        })

      let pfx_assertions_res =
        result.all(
          list.map(raw.prefix_assertions, fn(ra) {
            use p <- result.try(parse_prefix(ra.prefix))
            Ok(SlurmPrefixAssertion(p, ra.max_prefix_length, ra.asn, ra.comment))
          }),
        )
      use pfx_assertions <- result.try(pfx_assertions_res)

      let bgpsec_assertions =
        list.map(raw.bgpsec_assertions, fn(ra) {
          SlurmBgpsecAssertion(ra.asn, ra.ski, ra.router_public_key, ra.comment)
        })

      Ok(SlurmFile(
        slurm_version: raw.slurm_version,
        prefix_filters: pfx_filters,
        bgpsec_filters: bgpsec_filters,
        prefix_assertions: pfx_assertions,
        bgpsec_assertions: bgpsec_assertions,
      ))
    }
    Error(err) -> Error("JSON parse error: " <> string.inspect(err))
  }
}

pub fn default_dn42_slurm() -> SlurmFile {
  let assert Ok(pfx_our) = parse_prefix("172.22.64.128/27")
  let assert Ok(pfx_bogus) = parse_prefix("172.20.99.0/24")

  SlurmFile(
    slurm_version: 1,
    prefix_filters: [
      SlurmPrefixFilter(
        prefix: Some(pfx_bogus),
        asn: Some(4_242_429_999),
        comment: Some("Filter out misconfigured upstream ROA"),
      ),
    ],
    bgpsec_filters: [],
    prefix_assertions: [
      SlurmPrefixAssertion(
        prefix: pfx_our,
        max_prefix_length: Some(29),
        asn: 4_242_420_125,
        comment: Some("Local DN42 origin assertion for slopbox anycast"),
      ),
    ],
    bgpsec_assertions: [],
  )
}
