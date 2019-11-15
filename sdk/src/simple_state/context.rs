// Copyright 2019 Cargill Incorporated
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use std::marker::PhantomData;

use crate::protocol::simple_state::{
    StateEntry, StateEntryBuilder, StateEntryList, StateEntryListBuilder, StateEntryValue,
    StateEntryValueBuilder, ValueType,
};
use crate::protos::{FromBytes, IntoBytes};
use crate::simple_state::addresser::Addresser;
use crate::simple_state::error::SimpleStateError;
use crate::TransactionContext;

/// KeyValueTransactionContext used to implement a simplified state consisting
/// of natural keys and a ValueType, an enum object used to represent a range primitive data types.
/// Uses an implementation of the Addresser trait to calculate radix addresses to be stored in the
/// KeyValueTransactionContext's internal transaction context.
pub struct KeyValueTransactionContext<'a, A, K>
where
    A: Addresser<K>,
{
    context: &'a mut dyn TransactionContext,
    addresser: A,
    /// PhantomData<K> is necessary for the K generic to be used with the Addresser trait, as K is not
    /// used in any other elements of the KeyValueTransactionContext struct.
    _key: PhantomData<K>,
}

impl<'a, A, K> KeyValueTransactionContext<'a, A, K>
where
    A: Addresser<K>,
{
    /// Creates a new KeyValueTransactionContext
    /// Implementations of the TransactionContext trait and Addresser trait must be provided.
    pub fn new(
        context: &'a mut dyn TransactionContext,
        addresser: A,
    ) -> KeyValueTransactionContext<'a, A, K> {
        KeyValueTransactionContext {
            context,
            addresser,
            _key: PhantomData,
        }
    }

    /// Calculates the address using the internal addresser then creates and serializes a
    /// StateEntryList protobuf message to be stored in the internal transaction context as bytes.
    ///
    /// Returns an `Ok(())` if the entry is successfully stored.
    ///
    /// # Arguments
    ///
    /// * `key` - The natural key to set the state entry at
    /// * `values` - The HashMap to be stored in state at the provided natural key
    pub fn set_state_entry(
        &self,
        key: &K,
        values: HashMap<String, ValueType>,
    ) -> Result<(), SimpleStateError> {
        let addr = self.addresser.compute(key.to_owned())?;

        // Creating the StateEntry from the key and values provided.
        let state_entry = self.create_state_entry(key, values)?;

        // Checking if there is an existing StateEntryList at the calculated address.
        match self.context.get_state_entry(&addr)? {
            Some(entry_list) => {
                let entry = StateEntryList::from_bytes(&entry_list)?;
                entry.entries().to_vec().push(state_entry);
                let bytes = entry.into_bytes()?;
                self.context.set_state_entry(addr, bytes)?;
            }
            None => {
                let entry_list = StateEntryListBuilder::new()
                    .with_state_entries(vec![state_entry])
                    .build()
                    .map_err(|err| SimpleStateError::ProtocolBuildError(Box::new(err)))?;

                let bytes = entry_list.into_bytes()?;
                self.context.set_state_entry(addr, bytes)?;
            }
        }
        Ok(())
    }

    /// Calculates the address using the internal addresser and deserializes the data fetched into
    /// a StateEntryList protobuf message, and translates this message to a HashMap, containing the
    /// stored value.
    ///
    /// Returns an optional HashMap which representes the value stored in state, returning `None`
    /// in case the address is not found.
    ///
    /// # Arguments
    ///
    /// * `key` - The natural key to fetch
    pub fn get_state_entry(
        &self,
        key: &K,
    ) -> Result<Option<HashMap<String, ValueType>>, SimpleStateError> {
        let addr = self.addresser.compute(key.to_owned())?;
        let normalized_key = self.addresser.normalize(key);
        // Retrieving the StateEntryList from the internal context.
        match self.context.get_state_entry(&addr)? {
            Some(state_entry_list) => {
                let entry_list = StateEntryList::from_bytes(&state_entry_list)?;
                // If we have retrieved a StateEntryList, iterating over the StateEntry objects
                // to find a match to the normalized key calculated from the provided key.
                match entry_list
                    .entries()
                    .to_vec()
                    .into_iter()
                    .find(|entry| entry.normalized_key() == normalized_key)
                {
                    Some(entry) => Ok(Some(
                        entry
                            .state_entry_values()
                            .iter()
                            .map(|entry| (entry.key().to_string(), entry.value().to_owned()))
                            .collect::<HashMap<String, ValueType>>(),
                    )),
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// Calculates the address using the internal addresser and retrieves the StateEntryList at the
    /// specified address. Then, after ensuring the StateEntry with the matching normalized key as
    /// the key provided, removes it from the StateEntryList. Then re-sets this filtered StateEntryList
    /// back into state.
    ///
    /// Returns an optional normalized key of the successfully deleted state entry, returning
    /// `None` if the StateEntryList or StateEntry is not found.
    ///
    /// # Arguments
    ///
    /// * `key` - The natural key to delete
    pub fn delete_state_entry(&self, key: &K) -> Result<Option<String>, SimpleStateError> {
        let addr = self.addresser.compute(key.to_owned())?;
        let normalized_key = self.addresser.normalize(key.to_owned());
        // Retrieving the StateEntryList at the calculated address.
        match self.context.get_state_entry(&addr)? {
            // If the StateEntryList is found, try to find the StateEntry with the matching
            // normalized key, and remove this from the StateEntryList.
            Some(state_entry_list) => {
                let entry_list = StateEntryList::from_bytes(&state_entry_list)?;
                // Since we retrieved, the StateEntryList, making sure there is a StateEntry with
                // the matching normalized key as the key provided.
                match entry_list
                    .entries()
                    .to_vec()
                    .into_iter()
                    .find(|entry| entry.normalized_key() == normalized_key)
                {
                    // If that normalized key is found, continue to remove its matches from the
                    // StateEntryList.
                    Some(_) => {
                        let filtered = entry_list
                            .entries()
                            .to_vec()
                            .into_iter()
                            .filter(|entry| entry.normalized_key() != normalized_key)
                            .collect::<Vec<StateEntry>>();
                        let new_entry_list = StateEntryListBuilder::new()
                            .with_state_entries(filtered)
                            .build()
                            .map_err(|err| SimpleStateError::ProtocolBuildError(Box::new(err)))?;
                        let bytes = new_entry_list.into_bytes()?;
                        self.context.set_state_entry(addr, bytes)?;
                        Ok(Some(normalized_key))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// For each value contained in the provided HashMap, creates and serializes a StateEntry
    /// protobuf message to be stored in the internal transaction context as bytes at the associated
    /// radix address that is calculated using the internal addresser.
    ///
    /// Returns an `Ok(())` if the provided entries were successfully stored.
    ///
    /// # Arguments
    ///
    /// * `entries` - Hashmap with the map to be stored in state at the associated natural key
    pub fn set_state_entries(
        &self,
        entries: HashMap<&K, HashMap<String, ValueType>>,
    ) -> Result<(), SimpleStateError> {
        let keys = entries.keys().map(ToOwned::to_owned).collect::<Vec<&K>>();
        let addresses = keys
            .iter()
            .map(|k| self.addresser.compute(&k))
            .collect::<Result<Vec<String>, SimpleStateError>>()?;
        // Creating a map of the StateEntryList to the address it is stored at
        let entry_list_map = self.get_state_entry_lists(&addresses)?;

        // Iterating over the provided HashMap to see if there is an existing StateEntryList at the
        // corresponding address. If there is one found, add the new StateEntry to the StateEntryList.
        // If there is none found, creates a new StateEntryList entry for that address.
        // Then, serializes the newly created StateEntryList to be set in the internal context.
        let entries_list = entries
            .iter()
            .map(|(key, values)| {
                let addr = self.addresser.compute(key)?;
                let state_entry = self.create_state_entry(key, values.to_owned())?;
                match entry_list_map.get(&addr) {
                    Some(entry_list) => {
                        let mut existing_entries = entry_list.entries().to_vec();
                        existing_entries.push(state_entry);
                        let entry_list = StateEntryListBuilder::new()
                            .with_state_entries(existing_entries)
                            .build()
                            .map_err(|err| SimpleStateError::ProtocolBuildError(Box::new(err)))?;
                        Ok((addr, entry_list.into_bytes()?))
                    }
                    None => {
                        let entry_list = StateEntryListBuilder::new()
                            .with_state_entries(vec![state_entry])
                            .build()
                            .map_err(|err| SimpleStateError::ProtocolBuildError(Box::new(err)))?;
                        Ok((addr, entry_list.into_bytes()?))
                    }
                }
            })
            .collect::<Result<Vec<(String, Vec<u8>)>, SimpleStateError>>()?;
        self.context.set_state_entries(entries_list)?;

        Ok(())
    }

    /// Calculates the addresses using the internal addresser and deserializes the data fetched into
    /// a StateEntryList protobuf message, then collects the StateEntry objects held in each list
    /// and translates these objects to the original HashMap value.
    ///
    /// Returns a HashMap of the normalized key to a HashMap of the value stored at the
    /// corresponding radix address within the StateEntry with a matching normalized key.
    ///
    /// # Arguments
    ///
    /// * `keys` - A list of natural keys to be fetched from state
    pub fn get_state_entries(
        &self,
        keys: Vec<&K>,
    ) -> Result<HashMap<String, HashMap<String, ValueType>>, SimpleStateError> {
        let addresses = keys
            .iter()
            .map(|k| self.addresser.compute(&k))
            .collect::<Result<Vec<String>, SimpleStateError>>()?;
        let normalized_keys = keys
            .iter()
            .map(|k| self.addresser.normalize(&k))
            .collect::<Vec<String>>();

        let state_entries: Vec<StateEntry> = self.flatten_state_entries(&addresses)?;

        // Now going to filter the StateEntry objects that actually have a matching normalized
        // key and convert the normalized key and value to be added to the returned HashMap.
        state_entries
            .iter()
            .filter(|entry| normalized_keys.contains(&entry.normalized_key().to_string()))
            .map(|entry| {
                let values = entry
                    .state_entry_values()
                    .iter()
                    .map(|val| (val.key().to_string(), val.value().to_owned()))
                    .collect::<HashMap<String, ValueType>>();
                Ok((entry.normalized_key().to_string(), values))
            })
            .collect::<Result<HashMap<String, HashMap<String, ValueType>>, SimpleStateError>>()
    }

    /// Fetches the relevant StateEntryLists, filters out any StateEntry objects with the matching
    /// key, and then resets the updated StateEntryLists.
    ///
    /// Returns a list of normalized keys of successfully deleted state entries.
    ///
    /// # Arguments
    ///
    /// * `keys` - A list of natural keys to be deleted from state
    pub fn delete_state_entries(&self, keys: Vec<K>) -> Result<Vec<String>, SimpleStateError> {
        let key_map: HashMap<String, String> = keys
            .iter()
            .map(|k| Ok((self.addresser.normalize(k), self.addresser.compute(k)?)))
            .collect::<Result<HashMap<String, String>, SimpleStateError>>()?;
        let state_entry_lists: HashMap<String, StateEntryList> = self.get_state_entry_lists(
            &key_map
                .values()
                .map(ToOwned::to_owned)
                .collect::<Vec<String>>(),
        )?;

        let mut deleted_keys = Vec::new();
        let mut new_entry_lists = Vec::new();
        key_map.iter().for_each(|(nkey, addr)| {
            // Fetching the StateEntryList at the corresponding address
            if let Some(list) = state_entry_lists.get(addr) {
                // The StateEntry objects will be filtered out of the StateEntryList if it has the
                // normalized key. This normalized key is added to a list of successfully filtered
                // entries to be returned.
                if list.contains(nkey.to_string()) {
                    let filtered = list
                        .entries()
                        .to_vec()
                        .into_iter()
                        .filter(|e| e.normalized_key() != nkey)
                        .collect::<Vec<StateEntry>>();
                    new_entry_lists.push((addr.to_string(), filtered));
                    deleted_keys.push(nkey.to_string());
                }
            }
        });
        // Setting the newly filtered StateEntryLists into state using the internal context
        self.context.set_state_entries(
            new_entry_lists
                .iter()
                .map(|(addr, filtered_list)| {
                    let new_entry_list = StateEntryListBuilder::new()
                        .with_state_entries(filtered_list.to_vec())
                        .build()
                        .map_err(|err| SimpleStateError::ProtocolBuildError(Box::new(err)))?;
                    Ok((addr.to_string(), new_entry_list.into_bytes()?))
                })
                .collect::<Result<Vec<(String, Vec<u8>)>, SimpleStateError>>()?,
        )?;

        Ok(deleted_keys)
    }

    /// Collects the StateEntryList objects from state and then uses flat_map
    /// to collect the StateEntry objects held within each StateEntryList.
    fn flatten_state_entries(
        &self,
        addresses: &[String],
    ) -> Result<Vec<StateEntry>, SimpleStateError> {
        Ok(self
            .get_state_entry_lists(addresses)?
            .values()
            .flat_map(|entry_list| entry_list.entries().to_vec())
            .collect::<Vec<StateEntry>>())
    }

    /// Collects the StateEntryList objects from the bytes fetched from state,
    /// then deserializes these into the native StateEntryList object
    fn get_state_entry_lists(
        &self,
        addresses: &[String],
    ) -> Result<HashMap<String, StateEntryList>, SimpleStateError> {
        self.context
            .get_state_entries(&addresses)?
            .iter()
            .map(|(addr, bytes_entry)| {
                Ok((addr.to_string(), StateEntryList::from_bytes(bytes_entry)?))
            })
            .collect::<Result<HashMap<String, StateEntryList>, SimpleStateError>>()
    }

    /// Creates a singular StateEntry object from the provided key and values.
    fn create_state_entry(
        &self,
        key: &K,
        values: HashMap<String, ValueType>,
    ) -> Result<StateEntry, SimpleStateError> {
        let state_values: Vec<StateEntryValue> = values
            .iter()
            .map(|(key, value)| {
                StateEntryValueBuilder::new()
                    .with_key(key.to_string())
                    .with_value(value.clone())
                    .build()
                    .map_err(|err| SimpleStateError::ProtocolBuildError(Box::new(err)))
            })
            .collect::<Result<Vec<StateEntryValue>, SimpleStateError>>()?;
        Ok(StateEntryBuilder::new()
            .with_normalized_key(self.addresser.normalize(key.to_owned()))
            .with_state_entry_values(state_values)
            .build()
            .map_err(|err| SimpleStateError::ProtocolBuildError(Box::new(err)))?)
    }
}
