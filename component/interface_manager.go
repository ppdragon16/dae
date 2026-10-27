/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"context"
	"path"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type callbackSet struct {
	pattern     string
	newCallback func(netlink.Link)
	delCallback func(netlink.Link)
}

type InterfaceManager struct {
	closed    context.Context
	close     context.CancelFunc
	mu        sync.Mutex
	callbacks []callbackSet
	upLinks   map[string]bool
	// operStates records the last observed operational state per interface so
	// that we can detect a link coming back up after an admin/carrier flap and
	// re-trigger the binding. The kernel removes the ingress qdisc and the
	// attached TC filters when a link goes down, and they are not re-added
	// automatically on re-up, which would silently break traffic steering.
	operStates map[string]netlink.LinkOperState
}

func NewInterfaceManager() *InterfaceManager {
	closed, toClose := context.WithCancel(context.Background())
	mgr := &InterfaceManager{
		callbacks:  make([]callbackSet, 0),
		closed:     closed,
		close:      toClose,
		upLinks:    make(map[string]bool),
		operStates: make(map[string]netlink.LinkOperState),
	}

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	subscribed := true
	if e := netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			log.Debug("LinkSubscribe:", err)
		},
		ListExisting: true,
	}); e != nil {
		subscribed = false
		log.Errorf("Failed to subscribe to link updates: %v", e)
	}

	go mgr.monitor(ch, done, subscribed)
	return mgr
}

func (m *InterfaceManager) monitor(ch <-chan netlink.LinkUpdate, done chan struct{}, subscribed bool) {
	for {
		select {
		case <-m.closed.Done():
			close(done)
			// A successful subscription needs a receiver after this loop
			// leaves: closing done makes the library close its netlink socket,
			// but a subscription goroutine already blocked sending an update
			// (link teardown itself bursts RTM_NEWLINK/DELLINK events) never
			// regains one and leaks. The drain ends when the socket close
			// unblocks the sender and the library closes ch. A failed
			// subscription has no sender, so nobody would ever close ch.
			if subscribed {
				go func() {
					for range ch {
					}
				}()
			}
			return
		case update := <-ch:
			ifName := update.Link.Attrs().Name

			switch update.Header.Type {
			case unix.RTM_NEWLINK:
				m.mu.Lock()
				newOperState := update.Link.Attrs().OperState
				prevOperState, known := m.operStates[ifName]
				_, exists := m.upLinks[ifName]

				// Re-bind in two situations: the interface is newly seen (first
				// appearance), or it was already known but its operational state
				// transitioned back to Up. The kernel removes the ingress qdisc and
				// the attached TC filters when a link goes down; on re-up they are
				// not re-added automatically, so without re-binding here the
				// dataplane silently loses all traffic steering on that interface
				// until the next full restart. (Port of upstream #1049.)
				rebind := false
				if !exists {
					rebind = true
					m.upLinks[ifName] = true
				} else if known && prevOperState != newOperState && newOperState == netlink.OperUp {
					rebind = true
				}
				m.operStates[ifName] = newOperState
				if !rebind {
					m.mu.Unlock()
					continue
				}
				m.upLinks[ifName] = true
				for _, callback := range m.callbacks {
					matched, err := path.Match(callback.pattern, ifName)
					if err != nil || !matched {
						continue
					}
					if callback.newCallback != nil {
						callback.newCallback(update.Link)
					}
				}
				m.mu.Unlock()

			case unix.RTM_DELLINK:
				m.mu.Lock()
				delete(m.upLinks, ifName)
				for _, callback := range m.callbacks {
					matched, err := path.Match(callback.pattern, ifName)
					if err != nil || !matched {
						continue
					}
					if callback.delCallback != nil {
						callback.delCallback(update.Link)
					}
				}
				m.mu.Unlock()
			}
		}
	}
}

func (m *InterfaceManager) RegisterWithPattern(pattern string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	links, err := netlink.LinkList()
	if err == nil {
		for _, link := range links {
			ifname := link.Attrs().Name
			if matched, err := path.Match(pattern, ifname); err == nil && matched {
				m.upLinks[ifname] = true

				if initCallback != nil {
					initCallback(link)
				}
			}
		}
	} else {
		log.Errorf("Failed to get link list: %v", err)
	}

	m.callbacks = append(m.callbacks, callbackSet{
		pattern:     pattern,
		newCallback: newCallback,
		delCallback: delCallback,
	})
}

func (m *InterfaceManager) Register(ifname string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	link, err := netlink.LinkByName(ifname)
	if err == nil {
		m.upLinks[ifname] = true

		if initCallback != nil {
			initCallback(link)
		}
	}

	m.callbacks = append(m.callbacks, callbackSet{
		pattern:     ifname,
		newCallback: newCallback,
		delCallback: delCallback,
	})
}

// Close cancels the context to stop the monitor goroutine
func (m *InterfaceManager) Close() error {
	m.close()
	return nil
}
