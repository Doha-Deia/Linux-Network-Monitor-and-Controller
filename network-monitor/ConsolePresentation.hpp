#ifndef CONSOLE_PRESENTATION_HPP
#define CONSOLE_PRESENTATION_HPP

#include "Aggregator.hpp"

class ConsolePresentation {
public:
    void render(const AggregationSnapshot& snapshot) const;
};

#endif
