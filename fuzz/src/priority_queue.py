

class MaxHeap():
    def __init__(self):
        self.queue = [] 
    
    def Max(self):
        return self.queue[0]

    def length(self):
        return len(self.queue)

    def get(self, index):
        return self.queue[index]
        
    def insert(self, item):
        # add item to list
        self.queue.append(item)
        last_index = len(self.queue) - 1
        # if it is first node
        if last_index == -1:
            self.queue[0] = item
        # compare with parent node 
        while 0 <= last_index:
            parent_index = self.parent(last_index)
            if 0 <= parent_index and self.queue[parent_index] < self.queue[last_index]:
                self.swap(last_index, parent_index)
                last_index = parent_index
            else:
                break 

    def delete(self):
        last_index = len(self.queue) - 1
        if last_index < 0: 
            return -1 
        self.swap(0, last_index)
        max_value = self.queue.pop()
        # sort whole heap again 
        self.maxHeapify(0)
        return max_value
    
    def maxHeapify(self, start):
        left_index = self.leftchild(start)
        right_index = self.rightchild(start)
        max_index = start

        if left_index <= len(self.queue) - 1 and self.queue[max_index] < self.queue[left_index]:
            max_index = left_index 
        
        if right_index <= len(self.queue) - 1 and self.queue[max_index] < self.queue[right_index]:
            max_index = right_index
        
        # if the i is not the max index, heapify again 
        if max_index != start:
            self.swap(start, max_index)
            self.maxHeapify(max_index)
    
    def swap(self, index, parent_index):
        self.queue[index], self.queue[parent_index] = self.queue[parent_index], self.queue[index]

    def parent(self, index):
        return (index - 1) // 2
    
    def leftchild(self, index):
        return index * 2 + 1
    
    def rightchild(self, index):
        return index * 2 + 1 
    