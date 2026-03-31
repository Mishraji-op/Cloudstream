package com.cncverse

import android.net.Uri
import com.lagradost.cloudstream3.*
import com.lagradost.cloudstream3.utils.*
import com.lagradost.cloudstream3.base64DecodeArray
import com.lagradost.cloudstream3.base64Encode
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue

class MovieBoxProvider : MainAPI() {
    companion object {
        var context: android.content.Context? = null
    }
    
    override var mainUrl = "https://api.inmoviebox.com"
    override var name = "MovieBox"
    override val hasMainPage = true
    override var lang = "ta"
    override val supportedTypes = setOf(TvType.Movie, TvType.TvSeries)

    private val secretKeyDefault = BuildConfig.MOVIEBOX_SECRET_KEY_DEFAULT
    private val secretKeyAlt = BuildConfig.MOVIEBOX_SECRET_KEY_ALT

    private fun normalizeMovieBoxSecret(raw: String): String {
        val s = raw.trim().trim('"', '\'', '“', '”', '‘', '’')
        val noWhitespace = buildString(s.length) {
            for (ch in s) if (!ch.isWhitespace()) append(ch)
        }

        return buildString(noWhitespace.length) {
            for (ch in noWhitespace) {
                append(
                    when (ch) {
                        // Common copy/paste confusables we’ve seen in MovieBox keys
                        'Ø', 'О', 'Ο' -> 'O'
                        'Е', 'Ε' -> 'E'
                        'В', 'Β' -> 'B'
                        'Х', 'Χ' -> 'X'
                        'Т', 'Τ' -> 'T'
                        'п' -> 'n'
                        // Lowercase Cyrillic letters that look like Latin
                        'а' -> 'a'
                        'е' -> 'e'
                        'о' -> 'o'
                        'с' -> 'c'
                        'х' -> 'x'
                        'у' -> 'y'
                        else -> ch
                    }
                )
            }
        }
    }

    private fun decodeMovieBoxSecret(rawSecret: String): ByteArray {
        val normalized = normalizeMovieBoxSecret(rawSecret)
        val variants = listOf(
            normalized,
            normalized.replace('-', '+').replace('_', '/'),
        ).distinct()

        fun paddedBase64(s: String): String {
            val mod = s.length % 4
            return if (mod == 0) s else s + "=".repeat(4 - mod)
        }

        for (variant in variants) {
            try {
                return base64DecodeArray(paddedBase64(variant))
            } catch (_: Throwable) {
                // try next
            }
            try {
                return base64DecodeArray(variant)
            } catch (_: Throwable) {
                // try next
            }
        }

        // Last-resort attempt: strip clearly invalid characters and retry.
        val stripped = normalized.filter { ch ->
            ch.isLetterOrDigit() || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_'
        }
        if (stripped.isNotEmpty() && stripped != normalized) {
            try {
                return base64DecodeArray(paddedBase64(stripped.replace('-', '+').replace('_', '/')))
            } catch (_: Throwable) {
                // fall through
            }
        }

        // Never crash the provider; fall back to bytes (may yield invalid signatures).
        return normalized.toByteArray(Charsets.UTF_8)
    }

    private val userAgent =
        "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)"

    private val xClientInfo =
        """{"package_name":"com.community.mbox.in","version_name":"3.0.03.0529.03","version_code":50020042,"os":"android","os_version":"16","device_id":"da2b99c821e6ea023e4be55b54d5f7d8","install_store":"ps","gaid":"d7578036d13336cc","brand":"google","model":"sdk_gphone64_x86_64","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}"""

    private val acceptJson = "application/json"
    private val contentTypeJson = "application/json"


    private fun md5(input: ByteArray): String {
        return MessageDigest.getInstance("MD5").digest(input)
            .joinToString("") { "%02x".format(it) }
    }

    private fun reverseString(input: String): String = input.reversed()

    private fun generateXClientToken(hardcodedTimestamp: Long? = null): String {
        val timestamp = (hardcodedTimestamp ?: System.currentTimeMillis()).toString()
        val reversed = reverseString(timestamp)
        val hash = md5(reversed.toByteArray())
        return "$timestamp,$hash"
    }

    private fun buildCanonicalString(
        method: String,
        accept: String?,
        contentType: String?,
        url: String,
        body: String?,
        timestamp: Long
    ): String {
        val parsed = Uri.parse(url)
        val path = parsed.path ?: ""
        
        // Build query string with sorted parameters (if any)
        val query = if (parsed.queryParameterNames.isNotEmpty()) {
            parsed.queryParameterNames.sorted().joinToString("&") { key ->
                parsed.getQueryParameters(key).joinToString("&") { value ->
                    "$key=$value"  // Don't URL encode here - Python doesn't do it
                }
            }
        } else ""
        
        val canonicalUrl = if (query.isNotEmpty()) "$path?$query" else path

        val bodyBytes = body?.toByteArray(Charsets.UTF_8)
        val bodyHash = if (bodyBytes != null) {
            val trimmed = if (bodyBytes.size > 102400) bodyBytes.copyOfRange(0, 102400) else bodyBytes
            md5(trimmed)
        } else ""

        val bodyLength = bodyBytes?.size?.toString() ?: ""
        return "${method.uppercase()}\n" +
                "${accept ?: ""}\n" +
                "${contentType ?: ""}\n" +
                "$bodyLength\n" +
                "${timestamp.toString()}\n" +
                "$bodyHash\n" +
                "$canonicalUrl"
    }

    private fun generateXTrSignature(
        method: String,
        accept: String?,
        contentType: String?,
        url: String,
        body: String? = null,
        useAltKey: Boolean = false,
        hardcodedTimestamp: Long? = null
    ): String {
        val timestamp = hardcodedTimestamp ?: System.currentTimeMillis()
        val canonical = buildCanonicalString(method, accept, contentType, url, body, timestamp)
        val secret = if (useAltKey) secretKeyAlt else secretKeyDefault
        val secretBytes = decodeMovieBoxSecret(secret)

        val mac = Mac.getInstance("HmacMD5")
        mac.init(SecretKeySpec(secretBytes, "HmacMD5"))
        val signature = mac.doFinal(canonical.toByteArray(Charsets.UTF_8))
        val signatureB64 = base64Encode(signature)

        return "$timestamp|2|$signatureB64"
    }

    private fun buildSignedHeaders(
        method: String,
        url: String,
        body: String? = null,
        extra: Map<String, String>? = null
    ): Map<String, String> {
        val xClientToken = generateXClientToken()
        val xTrSignature = generateXTrSignature(method, acceptJson, contentTypeJson, url, body)

        val headers = mutableMapOf(
            "user-agent" to userAgent,
            "accept" to acceptJson,
            "content-type" to contentTypeJson,
            "connection" to "keep-alive",
            "x-client-token" to xClientToken,
            "x-tr-signature" to xTrSignature,
            "x-client-info" to xClientInfo,
            "x-client-status" to "0",
        )
        if (extra != null) headers.putAll(extra)
        return headers
    }

     override val mainPage = mainPageOf(
        "1" to "Trending",
        "2" to "For You",
        "3" to "Hits",
        "4" to "Blockbusters",
        "5" to "Top Rated",
    )

    override suspend fun getMainPage(page: Int, request: MainPageRequest): HomePageResponse {
        // Show star popup on first visit (shared across all CNCVerse plugins)
        context?.let { StarPopupHelper.showStarPopupIfNeeded(it) }
        
        val url = "$mainUrl/wefeed-mobile-bff/subject-api/list"
        // Use the function argument for pagination; request.data is category ID.
        val jsonBody = """{"page": $page, "perPage": 12, "rate": ["0", "10"], "genre": "All"}"""
        val headers = buildSignedHeaders("POST", url, jsonBody)
        

            val requestBody = jsonBody.toRequestBody(contentTypeJson.toMediaType())
            val response = app.post(
                url,
                headers = headers,
                requestBody = requestBody
            )
            val responseBody = response.text
            // Use Jackson to parse the new API response structure
            val data = try {
                val mapper = jacksonObjectMapper()
                val root = mapper.readTree(responseBody)
                val items = root["data"]?.get("items") ?: return newHomePageResponse(emptyList())
                items.mapNotNull { item ->
                    val title = item["title"]?.asText() ?: return@mapNotNull null
                    val id = item["subjectId"]?.asText() ?: return@mapNotNull null
                    val coverImg = item["cover"]?.get("url")?.asText()
                    val subjectType = item["subjectType"]?.asInt() ?: 1
                    val type = when (subjectType) {
                        1 -> TvType.Movie
                        2 -> TvType.TvSeries
                        else -> TvType.Movie
                    }
                    newMovieSearchResponse(
                        name = title,
                        url = id,
                        type = type
                    ) {
                        posterUrl = coverImg
                    }
                }
            } catch (e: Exception) {
                null
            } ?: emptyList()

            return newHomePageResponse(
                listOf(
                    HomePageList(request.name, data)
                )
            )

    }

    override suspend fun search(query: String): List<SearchResponse> {
        val url = "$mainUrl/wefeed-mobile-bff/subject-api/search/v2"
        val escapedQuery = query.replace("\\", "\\\\").replace("\"", "\\\"")
        val jsonBody = """{"page": 1, "perPage": 10, "keyword": "$escapedQuery"}"""
        val headers = buildSignedHeaders("POST", url, jsonBody)
        val requestBody = jsonBody.toRequestBody(contentTypeJson.toMediaType())
        val response = app.post(
            url,
            headers = headers,
            requestBody = requestBody
        )
        val responseBody = response.text
        val mapper = jacksonObjectMapper()
        val root = mapper.readTree(responseBody)
        val results = root["data"]?.get("results") ?: return emptyList()
        val searchList = mutableListOf<SearchResponse>()
        for (result in results) {
            val subjects = result["subjects"] ?: continue
            for (subject in subjects) {
            val title = subject["title"]?.asText() ?: continue
            val id = subject["subjectId"]?.asText() ?: continue
            val coverImg = subject["cover"]?.get("url")?.asText()
            val subjectType = subject["subjectType"]?.asInt() ?: 1
            val type = when (subjectType) {
                        1 -> TvType.Movie
                        2 -> TvType.TvSeries
                        else -> TvType.Movie
                }
            searchList.add(
                newMovieSearchResponse(
                name = title,
                url = id,
                type = type
                ) {
                posterUrl = coverImg
                }
            )
            }
        }
        return searchList
    }

    override suspend fun load(url: String): LoadResponse? {
        val id = if (url.contains("get?subjectId")) {
            Uri.parse(url).getQueryParameter("subjectId") ?: url.substringAfterLast('/')
        } else {
            url.substringAfterLast('/')
        }
        val finalUrl = "$mainUrl/wefeed-mobile-bff/subject-api/get?subjectId=$id"
        val headers = buildSignedHeaders("GET", finalUrl, extra = mapOf("x-play-mode" to "2"))
        val response = app.get(finalUrl, headers = headers)
        if (response.code != 200) {
            throw ErrorLoadingException("Failed to load data: HTTP ${response.code}")
        }
        val responseBody = response.text
        val mapper = jacksonObjectMapper()
        val root = mapper.readTree(responseBody)
        val data = root["data"] ?: throw ErrorLoadingException("No data in response")

        val title = data["title"]?.asText() ?: throw ErrorLoadingException("No title found")
        val description = data["description"]?.asText()
        val releaseDate = data["releaseDate"]?.asText()
        val duration = data["duration"]?.asText()
        val genre = data["genre"]?.asText()
        // API returns imdbRatingValue like "7.7" (0–10 scale).
        val imdbRating = data["imdbRatingValue"]?.asText()?.toDoubleOrNull()
        val year = releaseDate?.substring(0, 4)?.toIntOrNull()
        val coverUrl = data["cover"]?.get("url")?.asText()
        val backgroundUrl = data["cover"]?.get("url")?.asText()
        val subjectType = data["subjectType"]?.asInt() ?: 1
        val countryName = data["countryName"]?.asText()

        // Parse cast information
        val actors = data["staffList"]?.mapNotNull { staff ->
            val staffType = staff["staffType"]?.asInt()
            if (staffType == 1) { // Actor
                val name = staff["name"]?.asText() ?: return@mapNotNull null
                val character = staff["character"]?.asText()
                val avatarUrl = staff["avatarUrl"]?.asText()
                ActorData(
                    Actor(name, avatarUrl),
                    roleString = character
                )
            } else null
        } ?: emptyList()

        // Parse tags/genres
        val tags = genre?.split(",")?.map { it.trim() } ?: emptyList()

        // Parse duration to minutes
        val durationMinutes = duration?.let { dur ->
            val regex = """(\d+)h\s*(\d+)m""".toRegex()
            val match = regex.find(dur)
            if (match != null) {
                val hours = match.groupValues[1].toIntOrNull() ?: 0
                val minutes = match.groupValues[2].toIntOrNull() ?: 0
                hours * 60 + minutes
            } else {
                dur.replace("m", "").toIntOrNull()
            }
        }

        val type = when (subjectType) {
            1 -> TvType.Movie
            2 -> TvType.TvSeries
            else -> TvType.Movie
        }

        if (type == TvType.TvSeries) {
            // For TV series, get season and episode information
            val seasonUrl = "$mainUrl/wefeed-mobile-bff/subject-api/season-info?subjectId=$id"
            val seasonHeaders = buildSignedHeaders("GET", seasonUrl)
            
            val seasonResponse = app.get(seasonUrl, headers = seasonHeaders)
            val episodes = mutableListOf<Episode>()
            
            if (seasonResponse.code == 200) {
                val seasonResponseBody = seasonResponse.text
                if (seasonResponseBody.isNotBlank()) {
                    val seasonRoot = mapper.readTree(seasonResponseBody)
                    val seasonData = seasonRoot["data"]
                    val seasons = seasonData?.get("seasons")
                    
                    seasons?.forEach { season ->
                        val seasonNumber = season["se"]?.asInt() ?: 1
                        val maxEpisodes = season["maxEp"]?.asInt() ?: 1
                        for (episodeNumber in 1..maxEpisodes) {
                            episodes.add(
                                newEpisode("$id|$seasonNumber|$episodeNumber") {
                                    this.name = "S${seasonNumber}E${episodeNumber}"
                                    this.season = seasonNumber
                                    this.episode = episodeNumber
                                    this.posterUrl = coverUrl
                                    this.description = "Season $seasonNumber Episode $episodeNumber"
                                }
                            )
                        }
                    }
                }
            }
            
            // If no episodes were found, add a fallback episode
            if (episodes.isEmpty()) {
                episodes.add(
                    newEpisode("$id|1|1") {
                        this.name = "Episode 1"
                        this.season = 1
                        this.episode = 1
                        this.posterUrl = coverUrl
                    }
                )
            }
            
            return newTvSeriesLoadResponse(title, finalUrl, type, episodes) {
                this.posterUrl = coverUrl
                this.backgroundPosterUrl = backgroundUrl
                this.plot = description
                this.year = year
                this.tags = tags
                this.actors = actors
                this.score = imdbRating?.let { Score.from10(it) }
                this.duration = durationMinutes
            }
        } else {
            return newMovieLoadResponse(title, finalUrl, type, id) {
                this.posterUrl = coverUrl
                this.backgroundPosterUrl = backgroundUrl
                this.plot = description
                this.year = year
                this.tags = tags
                this.actors = actors
                this.score = imdbRating?.let { Score.from10(it) }
                this.duration = durationMinutes
            }
        }
    }

    override suspend fun loadLinks(
        data: String,
        isCasting: Boolean,
        subtitleCallback: (SubtitleFile) -> Unit,
        callback: (ExtractorLink) -> Unit
    ): Boolean {
        try {
            val parts = data.split("|")
            val originalSubjectId = if (parts[0].contains("get?subjectId")) {
                Uri.parse(parts[0]).getQueryParameter("subjectId") ?: parts[0].substringAfterLast('/')
            } else if(parts[0].contains("/")) {
                parts[0].substringAfterLast('/')
            }
            else {
                parts[0]
            }
            // Cloudstream tests providers from search results directly (no episode context),
            // so default to S1E1 instead of 0/0 to avoid empty play-info responses.
            val season = if (parts.size > 1) (parts[1].toIntOrNull() ?: 1).coerceAtLeast(1) else 1
            val episode = if (parts.size > 2) (parts[2].toIntOrNull() ?: 1).coerceAtLeast(1) else 1
            val subjectUrl = "$mainUrl/wefeed-mobile-bff/subject-api/get?subjectId=$originalSubjectId"
            val subjectHeaders = buildSignedHeaders("GET", subjectUrl, extra = mapOf("x-play-mode" to "2"))
            
            val subjectResponse = app.get(subjectUrl, headers = subjectHeaders)
            val mapper = jacksonObjectMapper()
            val subjectIds = mutableListOf<Pair<String, String>>() // Pair of (subjectId, language)
            val subjectDataCache = mutableMapOf<String, com.fasterxml.jackson.databind.JsonNode>()
            var originalLanguageName = "Original"
            if (subjectResponse.code == 200) {
                val subjectResponseBody = subjectResponse.text
                if (subjectResponseBody.isNotBlank()) {
                    val subjectRoot = mapper.readTree(subjectResponseBody)
                    val subjectData = subjectRoot["data"]
                    if (subjectData != null) {
                        subjectDataCache[originalSubjectId] = subjectData
                    }
                    val dubs = subjectData?.get("dubs")
                    if (dubs != null && dubs.isArray) {
                        for (dub in dubs) {
                            val dubSubjectId = dub["subjectId"]?.asText()
                            val lanName = dub["lanName"]?.asText()
                            if (dubSubjectId != null && lanName != null) {
                                if (dubSubjectId == originalSubjectId) {
                                    originalLanguageName = lanName
                                } else {
                                    subjectIds.add(Pair(dubSubjectId, lanName))
                                }
                            }
                        }
                    }
                }
            }
            
            // Always add the original subject ID first as the default source with proper language name
            subjectIds.add(0, Pair(originalSubjectId, originalLanguageName))
            
            var hasAnyLinks = false

            suspend fun fetchSubjectData(subjectId: String): com.fasterxml.jackson.databind.JsonNode? {
                subjectDataCache[subjectId]?.let { return it }

                val url = "$mainUrl/wefeed-mobile-bff/subject-api/get?subjectId=$subjectId"
                val headers = buildSignedHeaders("GET", url, extra = mapOf("x-play-mode" to "2"))
                val resp = app.get(url, headers = headers)
                if (resp.code != 200) return null

                val body = resp.text
                if (body.isBlank()) return null
                val dataNode = mapper.readTree(body)?.get("data")
                if (dataNode != null) subjectDataCache[subjectId] = dataNode
                return dataNode
            }

            suspend fun emitResourceDetectorLinks(subjectId: String, language: String, subjectData: com.fasterxml.jackson.databind.JsonNode?): Boolean {
                val detectors = subjectData?.get("resourceDetectors")
                if (detectors == null || !detectors.isArray || detectors.isEmpty) return false

                var emitted = false

                suspend fun emitOne(url: String?, label: String?) {
                    val u = url?.trim().orEmpty()
                    if (u.isBlank()) return

                    val type = when {
                        u.startsWith("magnet:", ignoreCase = true) -> ExtractorLinkType.MAGNET
                        u.substringAfterLast('.', "").equals("mpd", ignoreCase = true) -> ExtractorLinkType.DASH
                        u.substringAfterLast('.', "").equals("torrent", ignoreCase = true) -> ExtractorLinkType.TORRENT
                        u.substringAfterLast('.', "").equals("m3u8", ignoreCase = true) -> ExtractorLinkType.M3U8
                        else -> ExtractorLinkType.VIDEO
                    }

                    callback.invoke(
                        newExtractorLink(
                            source = name,
                            name = if (label.isNullOrBlank()) {
                                "$name ($language)"
                            } else {
                                "$name ($language - $label)"
                            },
                            url = u,
                            type = type,
                        ) {
                            this.headers = mapOf(
                                "Referer" to mainUrl,
                                "User-Agent" to userAgent
                            )
                            this.quality = Qualities.Unknown.value
                        }
                    )
                    emitted = true
                }

                for (det in detectors) {
                    val downloadUrl = det["downloadUrl"]?.asText()
                    val resourceLink = det["resourceLink"]?.asText()
                    val codec = det["codecName"]?.asText()
                    val type = det["type"]?.asText()
                    val label = listOfNotNull(codec, type).filter { it.isNotBlank() }.joinToString(" ").ifBlank { null }

                    // Prefer signed direct CDN links when available.
                    emitOne(downloadUrl, label)
                    emitOne(resourceLink, label)

                    // Some payloads include resolutionList with more links.
                    val resList = det["resolutionList"]
                    if (resList != null && resList.isArray) {
                        for (res in resList) {
                            val rLabel = res["title"]?.asText() ?: res["resolution"]?.asText()
                            emitOne(res["downloadUrl"]?.asText(), rLabel)
                            emitOne(res["resourceLink"]?.asText(), rLabel)
                        }
                    }
                }
                return emitted
            }
            
            // Process each subjectId (including dubs)
            for ((subjectId, language) in subjectIds) {
                try {
                    val subjectData = fetchSubjectData(subjectId)

                    // Primary path: emit links from resourceDetectors (works even when play-info returns 406).
                    val emittedFromDetectors = emitResourceDetectorLinks(subjectId, language, subjectData)
                    if (emittedFromDetectors) {
                        hasAnyLinks = true
                        continue
                    }

                    val episodeCandidates = linkedSetOf(
                        Pair(season, episode),
                        Pair(1, 1),
                        Pair(0, 0)
                    )

                    for ((seCandidate, epCandidate) in episodeCandidates) {
                        val url = "$mainUrl/wefeed-mobile-bff/subject-api/play-info?subjectId=$subjectId&se=$seCandidate&ep=$epCandidate"
                        val headers = buildSignedHeaders("GET", url, extra = mapOf("x-play-mode" to "2"))

                        val response = app.get(url, headers = headers)
                        if (response.code != 200) continue

                        val responseBody = response.text
                        val root = mapper.readTree(responseBody)
                        val playData = root["data"]
                        val streams = playData?.get("streams")
                        if (streams == null || !streams.isArray || streams.isEmpty) {
                            continue
                        }
                        var foundStreamsForLanguage = false

                        for (stream in streams) {
                            val streamUrl = stream["url"]?.asText() ?: continue
                            val format = stream["format"]?.asText() ?: ""
                            val resolutions = stream["resolutions"]?.asText() ?: ""
                            val signCookie = stream["signCookie"]?.asText()?.takeIf { it.isNotBlank() }
                            val id = stream["id"]?.asText() ?: "$subjectId|$seCandidate|$epCandidate"

                            callback.invoke(
                                newExtractorLink(
                                    source = name,
                                    name = "$name ($language - $resolutions)",
                                    url = streamUrl,
                                    type = when {
                                        streamUrl.startsWith("magnet:", ignoreCase = true) -> ExtractorLinkType.MAGNET
                                        streamUrl.substringAfterLast('.', "").equals("mpd", ignoreCase = true) -> ExtractorLinkType.DASH
                                        streamUrl.substringAfterLast('.', "").equals("torrent", ignoreCase = true) -> ExtractorLinkType.TORRENT
                                        format.equals("HLS", ignoreCase = true) || streamUrl.substringAfterLast('.', "").equals("m3u8", ignoreCase = true) -> ExtractorLinkType.M3U8
                                        else -> ExtractorLinkType.VIDEO
                                    }
                                ) {
                                    val baseHeaders = mutableMapOf("Referer" to mainUrl)
                                    if (signCookie != null) baseHeaders["Cookie"] = signCookie
                                    this.headers = baseHeaders
                                    this.quality = Qualities.Unknown.value
                                }
                            )

                            try {
                                val subLink = "$mainUrl/wefeed-mobile-bff/subject-api/get-stream-captions?subjectId=$subjectId&streamId=$id"
                                val xClientToken = generateXClientToken()
                                val xTrSignature = generateXTrSignature("GET", "", "", subLink)
                                val headers = mapOf(
                                    "User-Agent" to userAgent,
                                    "Accept" to "",
                                    "X-Client-Info" to xClientInfo,
                                    "X-Client-Status" to "0",
                                    "Content-Type" to "",
                                    "X-Client-Token" to xClientToken,
                                    "x-tr-signature" to xTrSignature
                                )
                                val subResponse = app.get(subLink, headers = headers)
                                if (subResponse.code == 200) {
                                    val subBody = subResponse.text
                                    val subRoot = if (subBody.isBlank()) null else mapper.readTree(subBody)
                                    val extCaptions = subRoot?.get("data")?.get("extCaptions")
                                    if (extCaptions != null && extCaptions.isArray) {
                                        for (caption in extCaptions) {
                                            val captionUrl = caption["url"]?.asText() ?: continue
                                            val lang = caption["language"]?.asText()
                                                ?: caption["lanName"]?.asText()
                                                ?: caption["lan"]?.asText()
                                                ?: "Unknown"
                                            subtitleCallback.invoke(
                                                SubtitleFile(
                                                    url = captionUrl,
                                                    lang = "$lang ($language - $resolutions)"
                                                )
                                            )
                                        }
                                    }
                                }
                            } catch (_: Exception) {
                                // subtitles are best-effort
                            }

                            try {
                                val subLink1 = "$mainUrl/wefeed-mobile-bff/subject-api/get-ext-captions?subjectId=$subjectId&resourceId=$id&episode=0"
                                val xClientToken1 = generateXClientToken()
                                val xTrSignature1 = generateXTrSignature("GET", "", "", subLink1)
                                val headers1 = mapOf(
                                    "User-Agent" to userAgent,
                                    "Accept" to "",
                                    "X-Client-Info" to xClientInfo,
                                    "X-Client-Status" to "0",
                                    "Content-Type" to "",
                                    "X-Client-Token" to xClientToken1,
                                    "x-tr-signature" to xTrSignature1
                                )
                                val subResponse1 = app.get(subLink1, headers = headers1)
                                if (subResponse1.code == 200) {
                                    val subBody = subResponse1.text
                                    val subRoot = if (subBody.isBlank()) null else mapper.readTree(subBody)
                                    val extCaptions = subRoot?.get("data")?.get("extCaptions")
                                    if (extCaptions != null && extCaptions.isArray) {
                                        for (caption in extCaptions) {
                                            val captionUrl = caption["url"]?.asText() ?: continue
                                            val lang = caption["lan"]?.asText()
                                                ?: caption["lanName"]?.asText()
                                                ?: caption["language"]?.asText()
                                                ?: "Unknown"
                                            subtitleCallback.invoke(
                                                SubtitleFile(
                                                    url = captionUrl,
                                                    lang = "$lang ($language - $resolutions)"
                                                )
                                            )
                                        }
                                    }
                                }
                            } catch (_: Exception) {
                                // subtitles are best-effort
                            }

                            hasAnyLinks = true
                            foundStreamsForLanguage = true
                        }

                        // We found working streams for this language; no need to retry se/ep candidates.
                        if (foundStreamsForLanguage) break
                    }
                } catch (e: Exception) {
                    continue
                }
            }
            
            return hasAnyLinks
              
        } catch (e: Exception) {
            return false
        }
    }
}

data class MovieBoxMainResponse(
    val code: Int? = null,
    val message: String? = null,
    val data: MovieBoxData? = null
)

data class MovieBoxData(
    val subjectId: String? = null,
    val subjectType: Int? = null,
    val title: String? = null,
    val description: String? = null,
    val releaseDate: String? = null,
    val duration: String? = null,
    val genre: String? = null,
    val cover: MovieBoxCover? = null,
    val countryName: String? = null,
    val language: String? = null,
    val imdbRatingValue: String? = null,
    val staffList: List<MovieBoxStaff>? = null,
    val hasResource: Boolean? = null,
    val resourceDetectors: List<MovieBoxResourceDetector>? = null,
    val year: Int? = null,
    val durationSeconds: Int? = null,
    val dubs: List<MovieBoxDub>? = null
)

data class MovieBoxCover(
    val url: String? = null,
    val width: Int? = null,
    val height: Int? = null,
    val size: Int? = null,
    val format: String? = null
)

data class MovieBoxStaff(
    val staffId: String? = null,
    val staffType: Int? = null,
    val name: String? = null,
    val character: String? = null,
    val avatarUrl: String? = null
)

data class MovieBoxResourceDetector(
    val type: Int? = null,
    val totalEpisode: Int? = null,
    val totalSize: String? = null,
    val uploadTime: String? = null,
    val uploadBy: String? = null,
    val resourceLink: String? = null,
    val downloadUrl: String? = null,
    val source: String? = null,
    val firstSize: String? = null,
    val resourceId: String? = null,
    val postId: String? = null,
    val extCaptions: List<MovieBoxCaption>? = null,
    val resolutionList: List<MovieBoxResolution>? = null,
    val subjectId: String? = null,
    val codecName: String? = null
)

data class MovieBoxResolution(
    val episode: Int? = null,
    val title: String? = null,
    val resourceLink: String? = null,
    val linkType: Int? = null,
    val size: String? = null,
    val uploadBy: String? = null,
    val resourceId: String? = null,
    val postId: String? = null,
    val extCaptions: List<MovieBoxCaption>? = null,
    val se: Int? = null,
    val ep: Int? = null,
    val sourceUrl: String? = null,
    val resolution: Int? = null,
    val codecName: String? = null,
    val duration: Int? = null,
    val requireMemberType: Int? = null,
    val memberIcon: String? = null
)

data class MovieBoxCaption(
    val url: String? = null,
    val label: String? = null,
    val language: String? = null
)

data class MovieBoxSeasonResponse(
    val code: Int? = null,
    val message: String? = null,
    val data: MovieBoxSeasonData? = null
)

data class MovieBoxSeasonData(
    val subjectId: String? = null,
    val subjectType: Int? = null,
    val seasons: List<MovieBoxSeason>? = null
)

data class MovieBoxSeason(
    val se: Int? = null,
    val maxEp: Int? = null,
    val allEp: String? = null,
    val resolutions: List<MovieBoxSeasonResolution>? = null
)

data class MovieBoxSeasonResolution(
    val resolution: Int? = null,
    val epNum: Int? = null
)

data class MovieBoxStreamResponse(
    val code: Int? = null,
    val message: String? = null,
    val data: MovieBoxStreamData? = null
)

data class MovieBoxStreamData(
    val streams: List<MovieBoxStream>? = null,
    val title: String? = null
)

data class MovieBoxStream(
    val format: String? = null,
    val id: String? = null,
    val url: String? = null,
    val resolutions: String? = null,
    val size: String? = null,
    val duration: Int? = null,
    val codecName: String? = null,
    val signCookie: String? = null
)

data class MovieBoxDub(
    val subjectId: String? = null,
    val lanName: String? = null,
    val lanCode: String? = null,
    val original: Boolean? = null,
    val type: Int? = null
)
