#ifndef LRU_CACHE_H
#define LRU_CACHE_H

#include <iostream>
#include <vector>
#include <map>
#include <string>


using namespace std;

template <class K, class T>
struct LRUCacheEntry
{
    K key;
    T data;
    LRUCacheEntry * prev;
    LRUCacheEntry * next;
};

template <class K, class T>
class LRUCache
{
public:
    LRUCache(size_t sz) : head(NULL), tail(NULL){
        entries = new LRUCacheEntry<K, T>[sz];
        int i;
        for (i = 0; i < sz; i++)
        {    
            freeEntries.push_back(entries + i);
        }
        cout<<" Constructed Cache with size "<<sz<<endl;
        head = tail = NULL;
    }

    ~LRUCache(){ 
        _m.clear();
        delete[] entries;        
     }

    bool containsKey(K key) { return _m.find(key) != _m.end(); }
    size_t size() const
    {
        return _m.size();
    }

    void put(K key, T data){
        cout<<" Put call for Key:  "<<key <<" Current Size "<<size()<<endl;
        if( !replace(key,data))
        {
            LRUCacheEntry<K, T> * entry;
            if (freeEntries.size() > 0){
                entry = freeEntries.back();
                freeEntries.pop_back();
            }
            else{
                // no free entries
                cout<<"Reusing Space in Cache started rotation "<<endl;
                entry = tail;
                if (tail->prev != NULL)
                {
                    tail->prev->next = NULL;
                    tail = tail->prev;
                }
                _m.erase(entry->key);
                // POC TODO FIXME the call below is specific to case when T is shared_ptr<FileNode>
                // Currently this data is not getting deleted even when use_count is going to zero
                // forcefully deleting it. 
                delete entry->data.get();
            }

            _m[key] = entry;
            entry->key = key;
            entry->data = data;
            entry->next = head;
            entry->prev = NULL;
            if (head != NULL){
                head->prev = entry;
            }
            else
            {
                head = tail = entry;
            }

            head = entry;
        }
    }

T get(K key) {
    if (containsKey(key))
    {
        LRUCacheEntry<K, T> * entry = _m[key];

        if (entry != head){
            if (entry->next != NULL)
            entry->next->prev = entry->prev;

            entry->prev->next = entry->next;
            if (entry == tail) tail = entry->prev;

            entry->next = head;
            entry->prev = NULL;
            head->prev = entry;  // added this
            head = entry;
        }
        return entry->data;
    }
    else
    {
        return T();
    }
}

void remove(K key)
{
    cout<<" Remove callin  Cache with size "<<key <<" Current Size "<<size()<<endl;
    if( containsKey(key) )
    {
        LRUCacheEntry<K, T> *entry = _m[key];
        _m.erase(key);
        
        if( entry == head )
        {
            head = entry->next;
            head->prev = NULL;
        }
        else if( entry == tail )
        {
            tail = entry->prev;
            tail->next = NULL;
        }
        else
        {
            if (entry->prev != NULL)
            {
                entry->prev->next = entry->next;
                if( entry->next != NULL )
                {
                    entry->next->prev = entry->prev;
                }
            }
        }
        freeEntries.push_back(entry);
    }
}

bool replaceKey(K oldKey, K newKey)
{
    bool retval = true;
    if( containsKey(oldKey) )
    {
        LRUCacheEntry<K, T> *entry = _m[oldKey];
        _m.erase(oldKey);
        entry->key = newKey;
        _m[newKey] = entry;
        get(newKey);
    }
    else
    {
        return false;
    }
    return retval;
}

void print(){
    LRUCacheEntry<K, T> * entry = head;
    while (entry != NULL){
        cout << entry->data << " ";
        entry = entry->next;
    }
    cout << endl;
}
private:
    bool replace(K key, T data)
    {
        bool retval = true;
        if( containsKey(key) )
        {
            LRUCacheEntry<K, T> *tempEntry = _m[key];
            tempEntry->data = data;
            get(key);
        }
        else
        {
            retval = false;
        }
        return retval;
    }

    map<K, LRUCacheEntry<K, T> *> _m;
    LRUCacheEntry<K, T> * head, *tail, *entries;
    vector<LRUCacheEntry<K, T> *> freeEntries;
};
#endif
