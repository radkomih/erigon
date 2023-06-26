package merkle_tree

import (
	"sync"

	"github.com/Giulio2002/sharedbuffer"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/common/length"
	"github.com/ledgerwatch/erigon/cl/utils"
)

var globalHasher *merkleHasher

const initialBufferSize = 0 // it is whatever

// merkleHasher is used internally to provide shared buffer internally to the merkle_tree package.
type merkleHasher struct {
	// internalBuffer is the shared buffer we use for each operation
	internalBuffer           [][32]byte
	internalBufferForSSZList [][32]byte
	// mu is the lock to ensure thread safety
	mu  sync.Mutex
	mu2 sync.Mutex // lock onto ssz list buffer
}

func newMerkleHasher() *merkleHasher {
	return &merkleHasher{
		internalBuffer: make([][32]byte, initialBufferSize),
	}
}

// merkleizeTrieLeaves returns intermediate roots of given leaves.
func (m *merkleHasher) merkleizeTrieLeavesFlat(leaves []byte, out []byte, limit uint64) (err error) {
	depth := GetDepth(limit)
	if len(leaves) == 0 {
		copy(out, ZeroHashes[depth][:])
		return nil
	}

	layer, cancelfn := sharedbuffer.Make(len(leaves) + ((len(leaves)/32)%2)*length.Hash)
	defer cancelfn()
	copy(layer, leaves)
	layer = layer[:len(leaves)]

	if err = m.merkleizeTrieLeavesFlatInPlace(layer, limit); err != nil {
		return
	}
	copy(out, layer[:length.Hash])
	return
}

// merkleizeTrieLeaves returns intermediate roots of given leaves.
func (m *merkleHasher) merkleizeTrieLeavesFlatInPlace(layer []byte, limit uint64) (err error) {
	for i := uint8(0); i < GetDepth(limit); i++ {
		layerLen := len(layer)
		if layerLen%64 != 0 {
			layer = append(layer, ZeroHashes[i][:]...)
		}
		if err := HashByteSlice(layer, layer); err != nil {
			return err
		}
		layer = layer[:len(layer)/2]
	}
	return
}

// getBuffer provides buffer of given size.
func (m *merkleHasher) getBuffer(size int) [][32]byte {
	if size > len(m.internalBuffer) {
		m.internalBuffer = make([][32]byte, size*2)
	}
	return m.internalBuffer[:size]
}

// getBuffer provides buffer of given size.
func (m *merkleHasher) getBufferForSSZList(size int) [][32]byte {
	if size > len(m.internalBufferForSSZList) {
		m.internalBufferForSSZList = make([][32]byte, size*2)
	}
	return m.internalBufferForSSZList[:size]
}

func (m *merkleHasher) getBufferFromFlat(xs []byte) [][32]byte {
	buf := m.getBuffer(len(xs) / 32)
	for i := 0; i < len(xs)/32; i = i + 1 {
		copy(buf[i][:], xs[i*32:(i+1)*32])
	}
	return buf
}

func (m *merkleHasher) transactionsListRoot(transactions [][]byte) ([32]byte, error) {
	leaves, cancelfn := sharedbuffer.Make(len(transactions) * length.Hash)
	defer cancelfn()
	for i, transaction := range transactions {
		transactionLength := uint64(len(transaction))

		formattedTransaction, cancelfn2 := sharedbuffer.Make(len(transaction) + (length.Hash - (len(transaction) % length.Hash)))
		copy(formattedTransaction, transaction)
		var out [32]byte
		err := m.merkleizeTrieLeavesFlat(formattedTransaction, out[:], 33554432)
		if err != nil {
			cancelfn2()
			return [32]byte{}, err
		}

		lengthRoot := Uint64Root(transactionLength)
		out = utils.Keccak256(out[:], lengthRoot[:])
		copy(leaves[i*length.Hash:], out[:])
		cancelfn2()
	}
	err := MerkleRootFromFlatLeavesWithLimit(leaves, leaves, 1048576)
	if err != nil {
		return libcommon.Hash{}, err
	}

	countRoot := Uint64Root(uint64(len(transactions)))

	return utils.Keccak256(leaves[:length.Hash], countRoot[:]), nil
}
