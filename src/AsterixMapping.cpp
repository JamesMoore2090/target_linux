#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Structure to hold our mapping pair
struct AsterixMapping {
    std::string source; // e.g., "asterix.048_010_SAC"
    std::string target; // e.g., "Cat48_SAC"
};

class AsterixConfigParser {
private:
    // Outer Map: Category Name (e.g., "CAT_48_MAP")
    // Inner Map: Field Key (e.g., "SAC") -> Mapping Struct
    std::map<std::string, std::map<std::string, AsterixMapping>> config_data;

public:
    bool loadConfig(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Could not open file: " << filename << std::endl;
            return false;
        }

        json j;
        file >> j;

        for (auto& [cat_name, fields] : j.items()) {
            for (auto& [field_key, mapping_values] : fields.items()) {
                AsterixMapping mapping;
                mapping.source = mapping_values["source"];
                mapping.target = mapping_values["target"];
                
                config_data[cat_name][field_key] = mapping;
            }
        }
        return true;
    }

    AsterixMapping getMapping(const std::string& category, const std::string& field) {
        if (config_data.count(category) && config_data[category].count(field)) {
            return config_data[category][field];
        }
        return {"NOT_FOUND", "NOT_FOUND"};
    }

    void printAll() {
        for (auto const& [cat, fields] : config_data) {
            std::cout << "--- " << cat << " ---" << std::endl;
            for (auto const& [key, map] : fields) {
                std::cout << key << " -> " << map.source << " | " << map.target << std::endl;
            }
        }
    }
};

// int main() {
//     AsterixConfigParser parser;

//     if (parser.loadConfig("mapping.json")) {
//         // Example 1: Look up a specific field
//         AsterixMapping m = parser.getMapping("CAT_48_MAP", "TrackNumber");
//         std::cout << "Target Name for TrackNumber: " << m.target << std::endl;

//         // Example 2: Print everything loaded
//         // parser.printAll();
//     }

//     return 0;
// }