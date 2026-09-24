// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;
import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.*;
import java.util.HashSet;

/** Bounded JSON with duplicate keys and nonstandard values refused. */
final class StrictJson {
    static JsonElement parse(String input) {
        if (input.length() > 65536) throw new IllegalArgumentException("JSON exceeds 64 KiB");
        try (JsonReader r = new JsonReader(new StringReader(input))) {
            r.setLenient(false);
            JsonElement result = read(r, 0);
            if (r.peek() != JsonToken.END_DOCUMENT) throw new IllegalArgumentException("trailing JSON");
            return result;
        } catch (IOException | IllegalStateException e) {
            throw new IllegalArgumentException("invalid JSON", e);
        }
    }
    private static JsonElement read(JsonReader r, int depth) throws IOException {
        if (depth > 16) throw new IllegalArgumentException("JSON nesting exceeds 16");
        return switch (r.peek()) {
            case BEGIN_OBJECT -> {
                r.beginObject(); JsonObject o = new JsonObject(); var names = new HashSet<String>();
                while (r.hasNext()) {
                    String name = r.nextName();
                    if (!names.add(name)) throw new IllegalArgumentException("duplicate JSON field");
                    o.add(name, read(r, depth + 1));
                }
                r.endObject(); yield o;
            }
            case BEGIN_ARRAY -> {
                r.beginArray(); JsonArray a = new JsonArray();
                while (r.hasNext()) a.add(read(r, depth + 1));
                r.endArray(); yield a;
            }
            case STRING -> new JsonPrimitive(r.nextString());
            case NUMBER -> new JsonPrimitive(new java.math.BigDecimal(r.nextString()));
            case BOOLEAN -> new JsonPrimitive(r.nextBoolean());
            case NULL -> { r.nextNull(); yield JsonNull.INSTANCE; }
            default -> throw new IllegalArgumentException("invalid JSON token");
        };
    }
}
