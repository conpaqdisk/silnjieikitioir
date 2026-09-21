// dep_graph.cpp
#include "dep_graph.h"
#include <queue>
#include <algorithm>

void DepGraph::add_node(const std::string& id) { nodes_.insert(id); }

void DepGraph::add_edge(const std::string& from, const std::string& to) {
    nodes_.insert(from); nodes_.insert(to);
    adj_[from].push_back(to);
}

bool DepGraph::topo(std::vector<std::string>& order, std::vector<std::string>& cycle_out) const {
    order.clear(); cycle_out.clear();

    // Build reverse graph: edges "X depends on Y" => Y -> X for topo order
    // We want dependencies BEFORE dependents, so edges are Y->X.
    std::unordered_map<std::string, int> indeg;
    std::unordered_map<std::string, std::vector<std::string>> rev;
    for (auto& n : nodes_) indeg[n] = 0;
    for (auto& kv : adj_) {
        for (auto& to : kv.second) {
            // kv.first depends on "to" -> to must come before kv.first
            rev[to].push_back(kv.first);
            indeg[kv.first]++;
        }
    }

    std::queue<std::string> q;
    for (auto& kv : indeg) if (kv.second == 0) q.push(kv.first);

    while (!q.empty()) {
        auto u = q.front(); q.pop();
        order.push_back(u);
        for (auto& v : rev[u]) {
            if (--indeg[v] == 0) q.push(v);
        }
    }

    if (order.size() == nodes_.size()) return true;

    // Cycle: report remaining nodes (best-effort, not a minimal cycle)
    for (auto& kv : indeg) if (kv.second > 0) cycle_out.push_back(kv.first);
    std::sort(cycle_out.begin(), cycle_out.end());
    return false;
}