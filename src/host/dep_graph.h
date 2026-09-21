// dep_graph.h
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

// Simple topological sort with cycle detection.
// add_node(id), add_edge(from, to) meaning "from depends on to".
// Returns true and fills order (dependencies first, then dependents)
// on success.  Returns false and fills cycle_out on cycle.
class DepGraph {
public:
    void add_node(const std::string& id);
    void add_edge(const std::string& from, const std::string& to);

    bool topo(std::vector<std::string>& order, std::vector<std::string>& cycle_out) const;

private:
    std::unordered_map<std::string, std::vector<std::string>> adj_;
    std::unordered_set<std::string> nodes_;
};