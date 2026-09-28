/*
Copyright 2024 Blnk Finance Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package watch

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
)

// activeRulesSet holds a set of active rules. The valid field is an atomic boolean to
// prevent race conditions from update of the set validity from concurrent goroutines.
type activeRulesSet struct {
	rules []Rule
	aggrConds []AggregateCond // aggregate conditions derived from the current set of active rules
	invalidatedCount atomic.Uint64
	level atomic.Uint64
	lock sync.Mutex
}

// [newActiveRulesSet] creates a new instance of activeRulesSet. The returned set is 
// invalid initially. This invalid state is ensured by setting [activeRulesSet.level] 
// to zero and [activeRulesSet.invalidatedCount] to 1. An activeRulesSet is valid if 
// [activeRulesSet.level] equals [activeRulesSet.invalidatedCount].
func newActiveRulesSet() *activeRulesSet {

	rc := &activeRulesSet{
		rules: make([]Rule, 0),
		aggrConds: make([]AggregateCond, 0),
	}
	rc.invalidatedCount.Add(1)
	rc.level.Store(0)
	return rc
}

var globalActiveRulesSet = newActiveRulesSet()

// populate gets active rules from the DB and populates the set if it is 
// invalidated, such as when rules are modified. If an error occurs, it logs 
// an error msg and returns the error. It also builds the aggregate conditions 
// based on the new rules, since aggregate conditions are constant for every 
// rule set.
func (rc *activeRulesSet) populate() error {

	// The validity check does not need to be mutex-protected
	if rc.isValid() {
		return nil
	}
	
	rc.lock.Lock()
	defer rc.lock.Unlock()

	log.Info().Msg("Populating rules set")

	currLevel := rc.invalidatedCount.Load()

	rules, err := getActiveRules()
	if err != nil {
		log.Error().Err(err).Msg("Failed to populate rules set")
		return fmt.Errorf("getActiveRules: %w", err)
	}

	rc.rules = rules
	// rebuild aggregate conditions based on the new rules
	rc.aggrConds = buildAggregateConds(rc.rules)
	rc.level.Store(currLevel)

	log.Info().Msg("Rules set successfully populated")
	return nil
}

func (rc *activeRulesSet) isValid() bool {
	return rc.level.Load() == rc.invalidatedCount.Load()
}

func (rc *activeRulesSet) invalidate() {
	rc.invalidatedCount.Add(1)
	log.Info().Msg("Rules set invalidated")
}

// [activeRulesSet.clear] resets the rules set to a state equivalent to a newly created set.
// Useful in tests to reset the rules set to a clean state after each test.
func (rc *activeRulesSet) clear() {
	rc.lock.Lock()
	defer rc.lock.Unlock()
	rc.rules = make([]Rule, 0)
	rc.aggrConds = make([]AggregateCond, 0)
	rc.level.Store(0)
	rc.invalidatedCount.Store(1)
}
