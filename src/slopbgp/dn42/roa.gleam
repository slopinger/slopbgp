import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import slopbgp/ip.{is_prefix_contained, parse_prefix}
import slopbgp/types.{
  type AsPathSegment, type IpPrefix, type RoaEntry, type RoaStatus, AsSequence,
  AsSet, RoaEntry, RoaInvalid, RoaNotFound, RoaValid,
}

pub fn parse_roa_line(line: String) -> Result(RoaEntry, String) {
  let trimmed = string.trim(line)
  case string.starts_with(trimmed, "#") || trimmed == "" {
    True -> Error("Comment or empty line")
    False -> {
      let cleaned = string.replace(trimmed, ";", "")
      let tokens = string.split(cleaned, " ")
      let non_empty = list.filter(tokens, fn(t) { t != "" })
      case non_empty {
        ["route", prefix_str, "max", max_str, "as", asn_str] -> {
          use prefix <- result.try(parse_prefix(prefix_str))
          use max_len <- result.try(
            int.parse(max_str)
            |> result.replace_error("Invalid max length: " <> max_str),
          )
          use asn <- result.try(
            int.parse(asn_str)
            |> result.replace_error("Invalid ASN: " <> asn_str),
          )
          Ok(RoaEntry(prefix: prefix, max_length: max_len, asn: asn))
        }
        _ -> Error("Invalid ROA line format: " <> line)
      }
    }
  }
}

pub fn parse_roa_content(content: String) -> List(RoaEntry) {
  let lines = string.split(content, "\n")
  list.filter_map(lines, parse_roa_line)
}

pub fn extract_origin_asn(as_path: List(AsPathSegment)) -> Option(Int) {
  case list.reverse(as_path) {
    [] -> None
    [last_seg, ..] ->
      case last_seg {
        AsSequence(asns) ->
          case list.reverse(asns) {
            [last_as, ..] -> Some(last_as)
            [] -> None
          }
        AsSet(asns) ->
          case asns {
            [first_as, ..] -> Some(first_as)
            [] -> None
          }
      }
  }
}

pub fn validate_route(
  prefix: IpPrefix,
  origin_asn: Int,
  roa_table: List(RoaEntry),
) -> RoaStatus {
  let covering_entries =
    list.filter(roa_table, fn(entry) {
      is_prefix_contained(prefix, entry.prefix)
    })

  case covering_entries {
    [] -> RoaNotFound
    _ -> {
      let is_valid =
        list.any(covering_entries, fn(entry) {
          prefix.length <= entry.max_length && origin_asn == entry.asn
        })
      case is_valid {
        True -> RoaValid
        False -> RoaInvalid
      }
    }
  }
}
