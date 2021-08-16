use std::error::Error;
use std::ffi::OsString;
use std::path::PathBuf;

use clap::{App, Arg};
use regex::Regex;
use reqwest::StatusCode;

pub enum FileFormat {
    json,
    txt,
    xml,
}

impl FileFormat {
    fn from_str(file_format: &str) -> Option<Self> {
        match file_format {
            "json" => Some(Self::json),
            "txt" => Some(Self::txt),
            "xml" => Some(Self::xml),
            _ => None,
        }
    }
}

pub enum StatusFilteringMode {
    Exclude,
    Include,
}

pub struct Config {
    /// Appends a slash to the end of requested URLs.
    append_slash: bool,

    /// Base url to which the wordlist and other additions will be appended.
    base_url: String,

    /// Password for basic authentication.
    basic_password: Option<String>,

    /// Username for basic authentication.
    basic_username: Option<String>,

    /// Whether output is coloured.
    colour_output: bool,

    /// Custom location for a config path.
    config_file: Option<PathBuf>,

    /// Execution should continue if wildcard requests return responses with
    /// successful status codes.
    continue_on_wildcard: bool,

    /// Key, value cookie pairs.
    cookies: Option<Vec<(String, String)>>,

    /// Delay in milliseconds between requests being sent.
    delay_ms: u32,

    /// Extensions (including '.' prefix) to be appended to requests.
    extensions: Option<Vec<String>>,

    /// Filter out responses with any of the specified number of lines.
    filter_num_lines: Option<Vec<u32>>,

    /// Filter out responses with any of the specified number of words.
    filter_num_words: Option<Vec<u32>>,

    /// Filter out responses which match any of the specified regexes.
    filter_regexes: Option<Vec<Regex>>,

    /// Filter out responses with any of the specified sizes.
    filter_sizes: Option<Vec<u32>>,

    /// Whether redirects should be followed.
    follow_redirects: bool,

    /// Generate words to scan by examining the response provided from the base URL
    /// and from any further URLs which are spidered down to the
    /// `word_generation_spider_depth`. The minimum length of these generated words
    /// is set by `word_generation_min_length`.
    generate_words: bool,

    /// Key, value header pairs.
    headers: Option<Vec<(String, String)>>,

    /// Should runtime interaction be enabled.
    interactive: bool,

    /// Base filename (excluding extensions) to which output should be written.
    output_file: Option<PathBuf>,

    /// Formats which the output should be written in.
    output_formats: Option<Vec<FileFormat>>,

    // TODO: Enum of proxy types: http(s), socks4(a), socks5(h)
    /// Proxy through which communications should go.
    proxy: Option<String>,

    /// Proxy through which requests are replayed through if the response was
    /// successful.
    proxy_on_success: Option<String>,

    /// Password for proxy authentication.
    proxy_password: Option<String>,

    /// Username for proxy authentication.
    proxy_username: Option<String>,

    /// Recurse through discovered directories.
    recurse: bool,

    /// Depth to which recursion should occur.
    recursion_depth: u8,

    /// Reads robots.txt (or equivalent) to generate requests.
    robots: bool,

    /// Spiders responses to generate further requests.
    spider: bool,

    /// The depth to which spidering should occur.
    spider_depth: u8,

    /// Response status codes which should be outputted.
    status_codes: Vec<StatusCode>,

    /// Whether responses should be filtered to include or exclude the status codes
    status_filtering_mode: StatusFilteringMode,

    /// Number of threads.
    threads: usize,

    /// Number of seconds until a request has timed out.
    timeout_seconds: u32,

    /// User-Agent header value
    user_agent: String,

    /// Whether TLS connection issues terminate execution.
    validate_tls: bool,

    // TODO: Some sort of logging level type?
    /// Level of output verbosity.
    verbosity: u8,

    /// The minimum length of generated words.
    word_gen_min_len: u8,

    /// The depth to which the base URL should be spidered to generate additional
    /// words. If `None` is set, there is no limit.
    word_gen_spider_depth: Option<u8>,

    /// The paths to wordlists which will be used to generate requests. If there is no
    /// wordlist provided, the list of directories to be scanned comes from stdin.
    /// These can be invalid.
    wordlists: Option<Vec<PathBuf>>,
}

// TODO: Result instead of panic? Use clap validation?
// TODO: Add query k, v pairs
// TODO: Add possible values where relevant, e.g. status codes
// TODO: Add SOCKS5(h)/SOCKS4(a) proxy
// TODO: Pull out the repetitive handling of multiple values into a function
// (likely a generic function)

impl Config {
    fn from_args<I, T>(args: I) -> Result<Self, Box<dyn Error>>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let matches = App::new("dirsect")
            .version("0.0.0")
            .about(
                "A directory bruteforcer with sensible defaults that doesn't need to be babysat.",
            )
            .arg(
                Arg::with_name("append_slash")
                    .short("f")
                    .long("append-slash")
                    .help("Appends a slash to the end of requested URLs."),
            )
            .arg(
                Arg::with_name("base_url")
                    .short("u")
                    .long("base-url")
                    .value_name("URL")
                    .required(true)
                    .help("The base URL for requests."),
            )
            .arg(
                Arg::with_name("basic_password")
                    .short("")
                    .long("basic-password")
                    .value_name("PASSWORD")
                    .help("Password for basic authentication"),
            )
            .arg(
                Arg::with_name("basic_username")
                    .short("")
                    .long("basic-username")
                    .value_name("USERNAME")
                    .help("Username for basic authentication"),
            )
            .arg(
                Arg::with_name("config_file")
                    .short("")
                    .long("config")
                    .value_name("PATH"),
            )
            .arg(
                Arg::with_name("continue_on_wildcard")
                    .short("")
                    .long("wildcard")
                    .help("Continue execution if wildcard responses are successful."),
            )
            .arg(
                Arg::with_name("cookies")
                    .short("c")
                    .long("cookies")
                    .value_name("COOKIES")
                    .multiple(true)
                    .help("Cookies to use with requests."),
            )
            .arg(
                Arg::with_name("delay")
                    .short("")
                    .long("delay")
                    .value_name("MILLISECONDS")
                    .default_value("0")
                    .validator(|delay| match u32::from_str_radix(&delay, 10) {
                        Ok(_) => Ok(()),
                        Err(_) => Err(String::from(
                            "cannot convert into an integer millisecond value",
                        )),
                    })
                    .help("Delay in milliseconds between requests."),
            )
            .arg(
                Arg::with_name("extensions")
                    .short("x")
                    .long("extensions")
                    .value_name("EXT1")
                    .multiple(true)
                    .use_delimiter(true)
                    .help("Extensions which will be appended to requests."),
            )
            .arg(
                Arg::with_name("filter_num_lines")
                    .short("")
                    .long("filter-num-lines")
                    .value_name("N")
                    .multiple(true)
                    .use_delimiter(true)
                    .help("Filter responses with any of the number of lines."),
            )
            .arg(
                Arg::with_name("filter_num_words")
                    .short("")
                    .long("filter-num-words")
                    .value_name("N")
                    .multiple(true)
                    .use_delimiter(true)
                    .help("Filter responses with any of the number of words."),
            )
            // "filter_regexes" as it's a container for multiple values
            // "--filter-regex" as only one is allowed per flag
            .arg(
                Arg::with_name("filter_regexes")
                    .short("")
                    .long("filter-regex")
                    .value_name("REGEX")
                    .multiple(true)
                    .help("Filter responses which match the regex. One regex per flag."),
            )
            .arg(
                Arg::with_name("filter_sizes")
                    .short("")
                    .long("filter-sizes")
                    .value_name("N")
                    .multiple(true)
                    .use_delimiter(true)
                    .help("Filter responses with any of the provided sizes."),
            )
            .arg(
                Arg::with_name("follow_redirects")
                    .short("r")
                    .long("follow-redirects")
                    .help("Follow redirects."),
            )
            .arg(
                Arg::with_name("generate_words")
                    .short("")
                    .long("generate-words")
                    .help("Generates additional words from responses."),
            )
            .arg(
                Arg::with_name("headers")
                    .short("H")
                    .long("headers")
                    .value_name("K:V")
                    .multiple(true)
                    .help("Header key, value pairs."),
            )
            .arg(
                Arg::with_name("interactive")
                    .short("")
                    .long("interactive")
                    .help("Run in interactive mode"),
            )
            .arg(
                Arg::with_name("negative_statuses")
                    .short("")
                    .long("negative-statuses")
                    .value_name("STATUS")
                    .conflicts_with("positive_statuses")
                    .multiple(true)
                    .use_delimiter(true)
                    .validator(|status| match u16::from_str_radix(&status, 10) {
                       Ok(_) => Ok(()),
                       Err(_) => Err("not a valid integer value for a status code".into())
                    })
                    .help("Include responses with any status code, except those provided."),
            )
            .arg(
                Arg::with_name("no_colour")
                    .short("")
                    .long("no-colour")
                    .help("Disable recursion."),
            )
            .arg(
                Arg::with_name("no_recurse")
                    .short("")
                    .long("no-recurse")
                    .help("Disable recursion."),
            )
            .arg(
                Arg::with_name("no_robots")
                    .short("")
                    .long("no-robots")
                    .help("Do not use robots.txt (or similar) to generate extra paths."),
            )
            .arg(
                Arg::with_name("no_spider")
                    .short("")
                    .long("no-spider")
                    .help("Do not generate additional requests by spidering discovered paths."),
            )
            .arg(
                Arg::with_name("no_tls_validation")
                    .short("k")
                    .long("no-tls-validation")
                    .help("Do not perform TLS validation."),
            )
            .arg(
                Arg::with_name("output_filename")
                    .short("o")
                    .long("output-filename")
                    .value_name("FILENAME")
                    .help("Output filename, excluding extensions."),
            )
            .arg(
                Arg::with_name("output_formats")
                    .short("")
                    .long("output-formats")
                    .value_name("FORMAT")
                    .multiple(true)
                    .use_delimiter(true)
                    .possible_values(&["json", "txt", "xml"])
                    .help("Desired file output formats."),
            )
            .arg(
                Arg::with_name("positive_statuses")
                    .short("")
                    .long("positive-statuses")
                    .value_name("STATUS")
                    .multiple(true)
                    .use_delimiter(true)
                    .validator(|status| match u16::from_str_radix(&status, 10) {
                       Ok(_) => Ok(()),
                       Err(_) => Err("not a valid integer value for a status code".into())
                    })
                    .help("Do not filter responses which match these status codes."),
            )
            .arg(
                Arg::with_name("proxy")
                    .short("")
                    .long("proxy")
                    .value_name("SCHEME://HOST:PORT")
                    .help("Proxy through which to send requests."),
            )
            .arg(
                Arg::with_name("proxy_on_success")
                    .short("")
                    .long("proxy-on-success")
                    .value_name("SCHEME://HOST:PORT")
                    .help("Proxy through which to replay successful requests."),
            )
            .arg(
                Arg::with_name("proxy_password")
                    .short("")
                    .long("proxy-password")
                    .value_name("PASSWORD")
                    .help("Password for proxy authentication."),
            )
            .arg(
                Arg::with_name("proxy_username")
                    .short("")
                    .long("proxy-username")
                    .value_name("USERNAME")
                    .help("Username for proxy authentication."),
            )
            .arg(
                Arg::with_name("recursion_depth")
                    .short("")
                    .long("recursion-depth")
                    .value_name("N")
                    .default_value("4")
                    .validator(|depth| match u8::from_str_radix(&depth, 10) {
                        Ok(_) => Ok(()),
                        Err(_) => Err("cannot convert into an integer value for recursion depth".into()),
                    })
                    .help("Depth to which to recurse (0 means no limit)."),
            )
            .arg(
                Arg::with_name("spider_depth")
                    .short("")
                    .long("spider-depth")
                    .value_name("N")
                    .default_value("0")
                    .validator(|depth| match u8::from_str_radix(&depth, 10) {
                        Ok(_) => Ok(()),
                        Err(_) => Err("cannot convert into an integer value for maximum spidering depth".into()),
                    })
                    .help("Depth to which spidering should occur (0 means no limit)."),
            )
            .arg(
                Arg::with_name("threads")
                    .short("")
                    .long("threads")
                    .value_name("N")
                    .default_value("10")
                    .validator(|threads| match usize::from_str_radix(&threads, 10) {
                        Ok(_) => Ok(()),
                        Err(_) => Err("cannot convert into an integer number of threads".into()),
                    })
                    .help("Number of threads to use."),
            )
            .arg(
                Arg::with_name("timeout")
                    .short("")
                    .long("timeout")
                    .value_name("SECONDS")
                    .default_value("10")
                    .validator(|timeout| match u32::from_str_radix(&timeout, 10) {
                        Ok(_) => Ok(()),
                        Err(_) => Err("cannot convert into an integer value for seconds before timeout".into()),
                    })
                    .help("How long until requests are considered to have timed out."),
            )
            .arg(
                Arg::with_name("user_agent")
                    .short("")
                    .long("user-agent")
                    .value_name("USER-AGENT")
                    .default_value("dirsect/0.0.0")
                    .help("Value of the User-Agent header."),
            )
            .arg(
                Arg::with_name("verbosity")
                    .short("v")
                    .long("verbosity")
                    .multiple(true)
                    .help("Increase the level of verbosity."),
            )
            .arg(
                Arg::with_name("word_gen_min_len")
                    .short("")
                    .long("word-gen-min-len")
                    .value_name("N")
                    .default_value("3")
                    .validator(|len| match u8::from_str_radix(&len, 10) {
                        Ok(_) => Ok(()),
                        Err(_) => Err("cannot convert into an integer value for minimum word length".into()),
                    })
                    .help("Min length of words generated, if word generation is enabled."),
            )
            .arg(
                Arg::with_name("word_gen_spider_depth")
                    .short("")
                    .long("word-gen-spider-depth")
                    .value_name("N")
                    .default_value("0")
                    .validator(|len| match u8::from_str_radix(&len, 10) {
                        Ok(_) => Ok(()),
                        Err(_) => Err("cannot convert into an integer value for the maximum spidering depth".into()),
                    })
                    .help("Max spidering depth when generating words, if word generation is enabled. 0 means no limit."),
            )
            .arg(
                Arg::with_name("wordlists")
                    .short("w")
                    .long("wordlists")
                    .value_name("WORDLIST")
                    .multiple(true)
                    .help("Filepaths of desired wordlists. Duplicates are removed."),
            )
            .get_matches_from(args);

        let append_slash = matches.is_present("append_slash");
        let base_url = matches.value_of("base_url").unwrap().to_owned();
        let basic_password = matches.value_of("basic_password").map(ToOwned::to_owned);
        let basic_username = matches.value_of("basic_username").map(ToOwned::to_owned);
        let colour_output = !matches.is_present("no_colour");
        let config_file = matches.value_of("config_file").map(PathBuf::from);
        let continue_on_wildcard = matches.is_present("continue_on_wildcard");
        let cookies = match matches.values_of("cookies") {
            Some(values) => {
                let mut cookies = Vec::with_capacity(values.len());

                for cookie in values {
                    // Cookie k, v pairs are split on first '=' char. The rest are considered part of
                    // the value. This should follow the spec correctly.
                    let mut split = cookie.splitn(2, "=");
                    let key = split
                        .next()
                        .expect("No key could be extracted from the cookie k, v pair.")
                        .trim()
                        .to_owned();
                    let value = split
                        .next()
                        .expect("No value could be extracted from the cookie k, v pair.")
                        .trim()
                        .to_owned();

                    cookies.push((key, value));
                }

                Some(cookies)
            }
            None => None,
        };
        let delay_ms = u32::from_str_radix(matches.value_of("delay").unwrap(), 10).unwrap();
        let extensions = match matches.values_of("extensions") {
            Some(values) => {
                let mut extensions = Vec::with_capacity(values.len());

                for extension in values {
                    let mut extension = extension.trim().to_owned();

                    if !extension.starts_with(".") {
                        extension = format!(".{}", extension);
                    }

                    extensions.push(extension);
                }

                Some(extensions)
            }
            None => None,
        };
        let filter_num_lines = match matches.values_of("filter_num_lines") {
            Some(values) => {
                let mut filters = Vec::with_capacity(values.len());

                for n in values {
                    let n = u32::from_str_radix(n.trim(), 10)?;
                    filters.push(n)
                }

                Some(filters)
            }
            None => None,
        };
        let filter_num_words = match matches.values_of("filter_num_words") {
            Some(values) => {
                let mut filters = Vec::with_capacity(values.len());

                for n in values {
                    let n = u32::from_str_radix(n.trim(), 10)?;
                    filters.push(n)
                }

                Some(filters)
            }
            None => None,
        };
        let filter_regexes = match matches.values_of("filter_regexes") {
            Some(values) => {
                // This may not work https://stackoverflow.com/questions/26368288/how-do-i-stop-iteration-and-return-an-error-when-iteratormap-returns-a-result
                // TODO: Check if this works, or if types cannot be deduced as rust-analyzer seems to think?
                // Some(values.map(Regex::new).collect()?)
                let mut regexes = Vec::with_capacity(values.len());

                for str in values {
                    regexes.push(Regex::new(str)?);
                }

                Some(regexes)
            }
            None => None,
        };
        let filter_sizes = match matches.values_of("filter_sizes") {
            Some(values) => {
                let mut filters = Vec::with_capacity(values.len());

                for n in values {
                    let n = u32::from_str_radix(n.trim(), 10)?;
                    filters.push(n)
                }

                Some(filters)
            }
            None => None,
        };
        let follow_redirects = matches.is_present("follow_redirects");
        let generate_words = matches.is_present("generate_words");
        let headers = match matches.values_of("headers") {
            Some(values) => {
                let mut headers = Vec::with_capacity(values.len());

                for header in values {
                    let mut split = header.splitn(2, "=");
                    let key = split
                        .next()
                        .expect("No key could be extracted from the cookie k, v pair.")
                        .trim()
                        .to_owned();
                    let value = split
                        .next()
                        .expect("No value could be extracted from the cookie k, v pair.")
                        .trim()
                        .to_owned();

                    headers.push((key, value));
                }

                Some(headers)
            }
            None => None,
        };
        let interactive = matches.is_present("interactive");
        let output_file = matches.value_of("output_filename").map(PathBuf::from);
        let output_formats = match matches.values_of("output_formats") {
            Some(values) => Some(
                values
                    .map(|fmt| FileFormat::from_str(fmt).unwrap())
                    .collect(),
            ),
            None => None,
        };
        // TODO: Proxy validation to check if it's actually valid, just blindly trusted here
        let proxy = matches.value_of("proxy").map(ToOwned::to_owned);
        // TODO: Proxy validation to check if it's actually valid, just blindly trusted here
        let proxy_on_success = matches.value_of("proxy_on_success").map(ToOwned::to_owned);
        let proxy_password = matches.value_of("proxy_password").map(ToOwned::to_owned);
        let proxy_username = matches.value_of("proxy_username").map(ToOwned::to_owned);
        let recurse = !matches.is_present("no_recurse");
        let recursion_depth =
            u8::from_str_radix(matches.value_of("recursion_depth").unwrap(), 10).unwrap();
        let robots = !matches.is_present("no_robots");
        let spider = !matches.is_present("no_spider");
        let spider_depth =
            u8::from_str_radix(matches.value_of("spider_depth").unwrap(), 10).unwrap();

        let status_filtering_mode;
        let status_codes =
            if matches.is_present("positive_statuses") || matches.is_present("negative_statuses") {
                // Custom statuses were provided
                let status_code_values = if matches.is_present("positive_statuses") {
                    status_filtering_mode = StatusFilteringMode::Include;

                    matches.values_of("positive_statuses").unwrap()
                } else {
                    status_filtering_mode = StatusFilteringMode::Exclude;

                    matches.values_of("negative_statuses").unwrap()
                };

                let mut status_codes = Vec::with_capacity(status_code_values.len());

                for status_code in status_code_values {
                    let status_code = u16::from_str_radix(status_code, 10)?;
                    let status_code = StatusCode::from_u16(status_code)?;
                    status_codes.push(status_code);
                }

                status_codes
            } else {
                // The default statuses
                status_filtering_mode = StatusFilteringMode::Include;

                // 200, 204, 301, 302, 307, 401, 403
                vec![
                    StatusCode::OK,
                    StatusCode::NO_CONTENT,
                    StatusCode::MOVED_PERMANENTLY,
                    StatusCode::FOUND,
                    StatusCode::TEMPORARY_REDIRECT,
                    StatusCode::UNAUTHORIZED,
                    StatusCode::FORBIDDEN,
                ]
            };

        let threads = usize::from_str_radix(matches.value_of("threads").unwrap(), 10).unwrap();
        let timeout_seconds =
            u32::from_str_radix(matches.value_of("timeout").unwrap(), 10).unwrap();
        let user_agent = matches.value_of("user_agent").unwrap().to_owned();
        let validate_tls = !matches.is_present("no_tls_validation");
        let verbosity = matches.occurrences_of("verbosity") as u8;
        let word_gen_min_len =
            u8::from_str_radix(matches.value_of("word_gen_min_len").unwrap(), 10).unwrap();
        let word_gen_spider_depth = match matches.value_of("word_gen_spider_depth") {
            Some(depth) => {
                let depth = matches.value_of("word_gen_spider_depth").unwrap();
                Some(u8::from_str_radix(depth.trim(), 10)?)
            }
            None => None,
        };
        let wordlists = match matches.values_of("wordlists") {
            Some(values) => Some(values.map(PathBuf::from).collect()),
            None => None,
        };

        Ok(Self {
            append_slash,
            base_url,
            basic_password,
            basic_username,
            colour_output,
            config_file,
            cookies,
            continue_on_wildcard,
            delay_ms,
            extensions,
            follow_redirects,
            generate_words,
            headers,
            interactive,
            filter_num_lines,
            filter_num_words,
            filter_regexes,
            filter_sizes,
            output_file,
            output_formats,
            proxy,
            proxy_on_success,
            proxy_password,
            proxy_username,
            recurse,
            recursion_depth,
            robots,
            spider,
            spider_depth,
            status_codes,
            status_filtering_mode,
            threads,
            timeout_seconds,
            user_agent,
            validate_tls,
            verbosity,
            word_gen_min_len,
            word_gen_spider_depth,
            wordlists,
        })
    }
}

// TODO: Tests
// TODO: Test multiple with and without spaces that need to be trimmed for all
