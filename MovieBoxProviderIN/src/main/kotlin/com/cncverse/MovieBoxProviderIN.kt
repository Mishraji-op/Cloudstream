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
import com.fasterxml.jackson.databind.JsonNode

class MovieBoxProviderIN : MainAPI() {
    companion object {
        var context: android.content.Context? = null
    }
    
    override var mainUrl = "https://api.inmoviebox.com"
    override var name = "MovieBox IN"
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

    override suspend fun getMainPage(page: Int, request: MainPageRequest): HomePageResponse {
        // Show star popup on first visit (shared across all CNCVerse plugins)
        context?.let { StarPopupHelper.showStarPopupIfNeeded(it) }
        
        val url = "$mainUrl/wefeed-mobile-bff/tab-operating?page=1&tabId=0&version="

        // Generate required security headers.
        val xClientToken = generateXClientToken()
        val xTrSignature = generateXTrSignature("GET", "application/json", "application/json", url)

        val headers = mapOf(
            "user-agent" to "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)",
            "accept" to "application/json",
            "content-type" to "application/json",
            "connection" to "keep-alive",
            "x-client-token" to xClientToken,
            "x-tr-signature" to xTrSignature,
            "x-client-info" to """{"package_name":"com.community.mbox.in","version_name":"3.0.03.0529.03","version_code":50020042,"os":"android","os_version":"16","device_id":"da2b99c821e6ea023e4be55b54d5f7d8","install_store":"ps","gaid":"d7578036d13336cc","brand":"google","model":"sdk_gphone64_x86_64","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}""",
            "x-client-status" to "0",
            "x-play-mode" to "2" // Optional, if needed for specific API behavior
        )

        val response = app.get(url, headers = headers)
        val responseBody = response.body?.string() ?: ""

        // Helper function to parse a 'subject' JSON object into your app's data model.
        fun parseSubject(subjectJson: JsonNode?): SearchResponse? {
            subjectJson ?: return null // Return null if the subject object is missing
            val subjectId = subjectJson["subjectId"]?.asText() ?: return null
            val title = subjectJson["title"]?.asText() ?: return null
            val coverUrl = subjectJson["cover"]?.get("url")?.asText()
            val subjectType = when (subjectJson["subjectType"]?.asInt()) {
                1 -> TvType.Movie
                2 -> TvType.TvSeries
                else -> TvType.Movie // Default to Movie
            }
            return newMovieSearchResponse(title, subjectId, subjectType) {
                this.posterUrl = coverUrl
            }
        }

        // Use Jackson to parse the new, multi-section API response structure.
        val homePageLists = try {
            val mapper = jacksonObjectMapper()
            val root = mapper.readTree(responseBody)
            val sections = root["data"]?.get("items") ?: return newHomePageResponse(emptyList())

            // Iterate through each section (e.g., Banners, Trending Now, etc.)
            sections.mapNotNull { section ->
                val title = section["title"]?.asText()?.let {
                    if (it.equals("banner", ignoreCase = true)) "🔥Top Picks" else it
                } ?: return@mapNotNull null
                val type = section["type"]?.asText()

                // Extract the list of media items based on the section type.
                val mediaList = when (type) {
                    "BANNER" -> section["banner"]?.get("banners")
                        ?.mapNotNull { bannerItem -> parseSubject(bannerItem["subject"]) }
                    "SUBJECTS_MOVIE" -> section["subjects"]
                        ?.mapNotNull { subjectItem -> parseSubject(subjectItem) }
                    "CUSTOM" -> section["customData"]?.get("items")
                        ?.mapNotNull { customItem -> parseSubject(customItem["subject"]) }
                    else -> null
                }

                // Only create a HomePageList if the section contains valid media items.
                if (mediaList.isNullOrEmpty()) {
                    null
                } else {
                    HomePageList(title, mediaList)
                }
            }
        } catch (e: Exception) {
            // In case of a parsing error, return an empty list.
            e.printStackTrace()
            emptyList()
        }

        return newHomePageResponse(homePageLists)
    }

    override suspend fun search(query: String): List<SearchResponse> {
        val url = "$mainUrl/wefeed-mobile-bff/subject-api/search/v2"
        val jsonBody = """{"page": 1, "perPage": 10, "keyword": "$query"}"""
        val xClientToken = generateXClientToken()
        val xTrSignature = generateXTrSignature("POST", "application/json", "application/json; charset=utf-8", url, jsonBody)
        val headers = mapOf(
            "user-agent" to "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)",
            "accept" to "application/json",
            "content-type" to "application/json",
            "connection" to "keep-alive",
            "x-client-token" to xClientToken,
            "x-tr-signature" to xTrSignature,
            "x-client-info" to """{"package_name":"com.community.mbox.in","version_name":"3.0.03.0529.03","version_code":50020042,"os":"android","os_version":"16","device_id":"da2b99c821e6ea023e4be55b54d5f7d8","install_store":"ps","gaid":"d7578036d13336cc","brand":"google","model":"sdk_gphone64_x86_64","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}""",
            "x-client-status" to "0"
        )
        val requestBody = jsonBody.toRequestBody("application/json".toMediaType())
        val response = app.post(
            url,
            headers = headers,
            requestBody = requestBody
        )
        val responseCode = response.code
        val responseBody = response.body.string()  
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
        val xClientToken = generateXClientToken()
        val xTrSignature = generateXTrSignature("GET", "application/json", "application/json", finalUrl)
        val headers = mapOf(
            "user-agent" to "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)",
            "accept" to "application/json",
            "content-type" to "application/json",
            "connection" to "keep-alive",
            "x-client-token" to xClientToken,
            "x-tr-signature" to xTrSignature,
            "x-client-info" to """{"package_name":"com.community.mbox.in","version_name":"3.0.03.0529.03","version_code":50020042,"os":"android","os_version":"16","device_id":"da2b99c821e6ea023e4be55b54d5f7d8","install_store":"ps","gaid":"d7578036d13336cc","brand":"google","model":"sdk_gphone64_x86_64","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}""",
            "x-client-status" to "0",
            "x-play-mode" to "2" // Optional, if needed for specific API behavior
        )
        val response = app.get(finalUrl, headers = headers)
        if (response.code != 200) {
            throw ErrorLoadingException("Failed to load data: ${response.body?.string()}")
        }
        val responseBody = response.body?.string() ?: throw ErrorLoadingException("Empty response body")
        val mapper = jacksonObjectMapper()
        val root = mapper.readTree(responseBody)
        val data = root["data"] ?: throw ErrorLoadingException("No data in response")

        val title = data["title"]?.asText() ?: throw ErrorLoadingException("No title found")
        val description = data["description"]?.asText()
        val releaseDate = data["releaseDate"]?.asText()
        val duration = data["duration"]?.asText()
        val genre = data["genre"]?.asText()
        val imdbRating = data["imdbRatingValue"]?.asText()?.toDoubleOrNull()?.times(10)?.toInt()
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
            val seasonXClientToken = generateXClientToken()
            val seasonXTrSignature = generateXTrSignature("GET", "application/json", "application/json", seasonUrl)
            val seasonHeaders = mapOf(
                "user-agent" to "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)",
                "accept" to "application/json",
                "content-type" to "application/json",
                "connection" to "keep-alive",
                "x-client-token" to seasonXClientToken,
                "x-tr-signature" to seasonXTrSignature,
                "x-client-info" to """{"package_name":"com.community.mbox.in","version_name":"3.0.03.0529.03","version_code":50020042,"os":"android","os_version":"16","device_id":"da2b99c821e6ea023e4be55b54d5f7d8","install_store":"ps","gaid":"d7578036d13336cc","brand":"google","model":"sdk_gphone64_x86_64","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}""",
                "x-client-status" to "0"
            )
            
            val seasonResponse = app.get(seasonUrl, headers = seasonHeaders)
            val episodes = mutableListOf<Episode>()
            
            if (seasonResponse.code == 200) {
                val seasonResponseBody = seasonResponse.body?.string()
                if (seasonResponseBody != null) {
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
                this.score = imdbRating?.let { Score.from10(it.toDouble()) }
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
                this.score = imdbRating?.let { Score.from10(it.toDouble()) }
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
            val subjectXClientToken = generateXClientToken()
            val subjectXTrSignature = generateXTrSignature("GET", "application/json", "application/json", subjectUrl)
            val subjectHeaders = mapOf(
                "user-agent" to "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)",
                "accept" to "application/json",
                "content-type" to "application/json",
                "connection" to "keep-alive",
                "x-client-token" to subjectXClientToken,
                "x-tr-signature" to subjectXTrSignature,
                "x-client-info" to """{"package_name":"com.community.mbox.in","version_name":"3.0.03.0529.03","version_code":50020042,"os":"android","os_version":"16","device_id":"da2b99c821e6ea023e4be55b54d5f7d8","install_store":"ps","gaid":"d7578036d13336cc","brand":"google","model":"sdk_gphone64_x86_64","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}""",
                "x-client-status" to "0"
            )
            
            val subjectResponse = app.get(subjectUrl, headers = subjectHeaders)
            val mapper = jacksonObjectMapper()
            val subjectIds = mutableListOf<Pair<String, String>>() // Pair of (subjectId, language)
            val subjectDataCache = mutableMapOf<String, com.fasterxml.jackson.databind.JsonNode>()
            var originalLanguageName = "Original"
            if (subjectResponse.code == 200) {
                val subjectResponseBody = subjectResponse.body?.string()
                if (subjectResponseBody != null) {
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
                val xClientToken = generateXClientToken()
                val xTrSignature = generateXTrSignature("GET", "application/json", "application/json", url)
                val headers = mapOf(
                    "user-agent" to "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)",
                    "accept" to "application/json",
                    "content-type" to "application/json",
                    "connection" to "keep-alive",
                    "x-client-token" to xClientToken,
                    "x-tr-signature" to xTrSignature,
                    "x-client-info" to """{"package_name":"com.community.mbox.in","version_name":"3.0.03.0529.03","version_code":50020042,"os":"android","os_version":"16","device_id":"da2b99c821e6ea023e4be55b54d5f7d8","install_store":"ps","gaid":"d7578036d13336cc","brand":"google","model":"sdk_gphone64_x86_64","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}""",
                    "x-client-status" to "0",
                    "x-play-mode" to "2"
                )
                val resp = app.get(url, headers = headers)
                if (resp.code != 200) return null

                val body = resp.body?.string().orEmpty()
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
                                "User-Agent" to "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)"
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

                    emitOne(downloadUrl, label)
                    emitOne(resourceLink, label)

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

                        val xClientToken = generateXClientToken()
                        val xTrSignature = generateXTrSignature("GET", "application/json", "application/json", url)
                        val headers = mapOf(
                            "user-agent" to "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)",
                            "accept" to "application/json",
                            "content-type" to "application/json",
                            "connection" to "keep-alive",
                            "x-client-token" to xClientToken,
                            "x-tr-signature" to xTrSignature,
                            "x-client-info" to """{"package_name":"com.community.mbox.in","version_name":"3.0.03.0529.03","version_code":50020042,"os":"android","os_version":"16","device_id":"da2b99c821e6ea023e4be55b54d5f7d8","install_store":"ps","gaid":"d7578036d13336cc","brand":"google","model":"sdk_gphone64_x86_64","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}""",
                            "x-client-status" to "0",
                            "x-play-mode" to "2"
                        )

                        val response = app.get(url, headers = headers)
                        if (response.code != 200) continue

                        val responseBody = response.body?.string() ?: continue
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
                                    "User-Agent" to "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)",
                                    "Accept" to "",
                                    "X-Client-Info" to """{"package_name":"com.community.mbox.in","version_name":"3.0.03.0529.03","version_code":50020042,"os":"android","os_version":"16","device_id":"da2b99c821e6ea023e4be55b54d5f7d8","install_store":"ps","gaid":"d7578036d13336cc","brand":"google","model":"sdk_gphone64_x86_64","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}""",
                                    "X-Client-Status" to "0",
                                    "Content-Type" to "",
                                    "X-Client-Token" to xClientToken,
                                    "x-tr-signature" to xTrSignature
                                )
                                val subResponse = app.get(subLink, headers = headers)
                                if (subResponse.code == 200) {
                                    val subBody = subResponse.body?.string().orEmpty()
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
                                    "User-Agent" to "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; Build/BP22.250325.006; Cronet/133.0.6876.3)",
                                    "Accept" to "",
                                    "X-Client-Info" to """{"package_name":"com.community.mbox.in","version_name":"3.0.03.0529.03","version_code":50020042,"os":"android","os_version":"16","device_id":"da2b99c821e6ea023e4be55b54d5f7d8","install_store":"ps","gaid":"d7578036d13336cc","brand":"google","model":"sdk_gphone64_x86_64","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}""",
                                    "X-Client-Status" to "0",
                                    "Content-Type" to "",
                                    "X-Client-Token" to xClientToken1,
                                    "x-tr-signature" to xTrSignature1
                                )
                                val subResponse1 = app.get(subLink1, headers = headers1)
                                if (subResponse1.code == 200) {
                                    val subBody = subResponse1.body?.string().orEmpty()
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
