package lock

import (
	"context"
	"database/sql"
	"fmt"
	logger "github.com/sirupsen/logrus"
	"time"
)

const (
	defaultPingDeadlineSecs = 10
	defaultPingIntervalSecs = 1
)

type (
	mysqlLocker struct {
		db    *sql.DB
		locks map[string]*mysqlLock
	}

	mysqlLock struct {
		name             string
		conn             *sql.Conn
		pingCtx          context.Context
		pingCtxCancelFn  context.CancelFunc
		pingIntervalSecs int
	}
)

func (l *mysqlLock) Release() error {
	l.pingCtxCancelFn()
	_, err := l.conn.ExecContext(context.Background(), "SELECT RELEASE_LOCK(?)", l.name)
	if err != nil {
		return err
	}
	return l.conn.Close()
}

func (l *mysqlLock) startPinger() {
	for {
		select {
		case <-l.pingCtx.Done():
			logger.WithField("name", l.name).Info("lock pinger stopped")
			return
		case <-time.After(time.Second * time.Duration(l.pingIntervalSecs)):
			deadline := time.Now().Add(time.Second * defaultPingDeadlineSecs)
			ctx, cancelFunc := context.WithDeadline(context.Background(), deadline)
			if err := l.conn.PingContext(ctx); err != nil {
				logger.WithError(err).WithField("name", l.name).Error("lock conn ping failed")
				cancelFunc()
				err = l.Release()
				logger.WithError(err).WithField("name", l.name).Info("lock release because ping failed")
				return
			}
			cancelFunc()
		}
	}
}

func NewMysqlLocker(db *sql.DB) Locker {
	return &mysqlLocker{db: db, locks: map[string]*mysqlLock{}}
}

func (l *mysqlLocker) Acquire(name string) (Lock, error) {
	conn, err := l.db.Conn(context.Background())
	if err != nil {
		return nil, err
	}

	row := conn.QueryRowContext(context.Background(), "SELECT GET_LOCK(?, ?)", name, 10)

	var result int
	if err := row.Scan(&result); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			logger.WithError(closeErr).
				WithField("cause", err).
				Error("failed closing sql conn")
		}
		return nil, err
	}

	if result == 1 {
		ctx, cancelFn := context.WithCancel(context.Background())
		lock := &mysqlLock{
			name:             name,
			conn:             conn,
			pingCtx:          ctx,
			pingCtxCancelFn:  cancelFn,
			pingIntervalSecs: defaultPingIntervalSecs,
		}
		logger.WithField("name", name).WithField("result", result).Info("lock success")
		go lock.startPinger()
		return lock, nil
	}

	if err = conn.Close(); err != nil {
		logger.WithError(err).
			WithField("result", result).
			Error("failed closing sql conn")
	}
	return nil, fmt.Errorf("failed to acquire lock, result: %d", result)
}
